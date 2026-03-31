import { execFileSync } from "node:child_process";
import type { TlsRecon } from "./schema.js";

const DOMAIN_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

function emptyResult(domain: string, issues: string[]): TlsRecon {
  return {
    domain,
    protocol: "unknown",
    cipher: "unknown",
    certificate: {
      issuer: "unknown",
      subject: "unknown",
      validFrom: "",
      validTo: "",
      daysUntilExpiry: -1,
      selfSigned: false,
      sans: [],
    },
    chainDepth: 0,
    grade: "F",
    issues,
  };
}

function extractField(output: string, pattern: RegExp): string {
  const match = output.match(pattern);
  return match?.[1]?.trim() ?? "";
}

function parseSans(output: string): string[] {
  const sans: string[] = [];
  const sanSection = output.match(
    /X509v3 Subject Alternative Name:\s*\n\s*(.+)/
  );
  if (sanSection) {
    const entries = sanSection[1].split(",").map((s) => s.trim());
    for (const entry of entries) {
      const dns = entry.match(/^DNS:(.+)$/);
      if (dns) sans.push(dns[1]);
    }
  }
  return sans;
}

function computeGrade(
  protocol: string,
  daysUntilExpiry: number,
  selfSigned: boolean,
  issues: string[]
): "A" | "B" | "C" | "D" | "F" {
  if (selfSigned || protocol === "unknown" || protocol.includes("SSL")) {
    return "F";
  }
  if (protocol.includes("TLSv1.0") || protocol === "TLSv1") {
    return "F";
  }
  if (daysUntilExpiry < 0) {
    return "D";
  }
  if (protocol.includes("TLSv1.1")) {
    return "D";
  }
  if (protocol.includes("TLSv1.2")) {
    if (daysUntilExpiry < 30 || issues.length > 0) {
      return "C";
    }
    return "B";
  }
  if (protocol.includes("TLSv1.3")) {
    if (daysUntilExpiry > 30) {
      return "A";
    }
    return "B";
  }
  return "C";
}

export function scanTls(domain: string): TlsRecon {
  if (!DOMAIN_REGEX.test(domain)) {
    return emptyResult(domain, ["Invalid domain"]);
  }

  // Pass empty stdin so openssl doesn't hang
  let connStdout: string;
  let connStderr: string;
  let connExitCode = 0;
  try {
    connStdout = execFileSync(
      "openssl",
      ["s_client", "-connect", `${domain}:443`, "-servername", domain],
      { input: "", encoding: "utf-8", timeout: 15_000, stdio: ["pipe", "pipe", "pipe"] },
    );
    connStderr = "";
  } catch (err: any) {
    connStdout = (err.stdout ?? "").toString();
    connStderr = (err.stderr ?? "").toString();
    connExitCode = err.status ?? 1;
  }

  if (!connStdout && connExitCode !== 0) {
    return emptyResult(domain, ["Connection failed: unable to reach host"]);
  }

  const fullOutput = connStdout + "\n" + connStderr;

  // Extract protocol and cipher from the connection output
  const protocol = extractField(fullOutput, /Protocol\s*:\s*(\S+)/) || "unknown";
  const cipher = extractField(fullOutput, /Cipher\s*:\s*(\S+)/) || "unknown";

  // Extract chain depth
  const depthMatch = fullOutput.match(/verify depth is (\d+)/);
  const chainDepth = depthMatch ? parseInt(depthMatch[1], 10) : 0;

  // Now parse the certificate details — two-step: get PEM from s_client, then parse with x509
  let pemOutput: string;
  try {
    pemOutput = execFileSync(
      "openssl",
      ["s_client", "-connect", `${domain}:443`, "-servername", domain],
      { input: "", encoding: "utf-8", timeout: 15_000, stdio: ["pipe", "pipe", "pipe"] },
    );
  } catch (err: any) {
    pemOutput = (err.stdout ?? "").toString();
  }

  let certOutput: string;
  try {
    certOutput = execFileSync(
      "openssl",
      ["x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
      { input: pemOutput, encoding: "utf-8", timeout: 10_000, stdio: ["pipe", "pipe", "pipe"] },
    );
  } catch (err: any) {
    certOutput = (err.stdout ?? "").toString();
  }

  // certOutput now comes from the two-step openssl pipeline above

  const subject = extractField(certOutput, /subject\s*=\s*(.+)/);
  const issuer = extractField(certOutput, /issuer\s*=\s*(.+)/);
  const validFrom = extractField(certOutput, /notBefore\s*=\s*(.+)/);
  const validTo = extractField(certOutput, /notAfter\s*=\s*(.+)/);
  const sans = parseSans(certOutput);

  // Compute days until expiry
  let daysUntilExpiry = -1;
  if (validTo) {
    const expiryDate = new Date(validTo);
    const now = new Date();
    daysUntilExpiry = Math.floor(
      (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );
  }

  // Detect self-signed
  const selfSigned = subject !== "" && issuer !== "" && subject === issuer;

  const issues: string[] = [];

  if (selfSigned) issues.push("Certificate is self-signed");
  if (daysUntilExpiry < 0) issues.push("Certificate has expired");
  else if (daysUntilExpiry < 30)
    issues.push(`Certificate expires in ${daysUntilExpiry} days`);
  if (protocol.includes("TLSv1.0") || protocol.includes("TLSv1.1"))
    issues.push(`Deprecated protocol: ${protocol}`);
  if (protocol.includes("SSL")) issues.push(`Insecure protocol: ${protocol}`);

  const grade = computeGrade(protocol, daysUntilExpiry, selfSigned, issues);

  return {
    domain,
    protocol,
    cipher,
    certificate: {
      issuer,
      subject,
      validFrom,
      validTo,
      daysUntilExpiry,
      selfSigned,
      sans,
    },
    chainDepth,
    grade,
    issues,
  };
}
