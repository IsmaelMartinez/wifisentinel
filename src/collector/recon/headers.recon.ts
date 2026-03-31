import { run } from "../exec.js";
import type { HeadersRecon, HeaderCheck } from "./schema.js";

interface HeaderSpec {
  header: string;
  evaluate: (value: string | null) => { status: "pass" | "fail" | "missing"; detail: string };
}

const SECURITY_HEADERS: HeaderSpec[] = [
  {
    header: "Strict-Transport-Security",
    evaluate(value) {
      if (!value) return { status: "missing", detail: "HSTS header not set" };
      const maxAge = value.match(/max-age=(\d+)/);
      const age = maxAge ? parseInt(maxAge[1], 10) : 0;
      if (age < 31536000) return { status: "fail", detail: `HSTS max-age too low (${age}s), recommended >=31536000` };
      const hasSub = value.includes("includeSubDomains");
      return { status: "pass", detail: hasSub ? "HSTS set with includeSubDomains" : "HSTS set" };
    },
  },
  {
    header: "Content-Security-Policy",
    evaluate(value) {
      if (!value) return { status: "missing", detail: "CSP header not set" };
      return { status: "pass", detail: `CSP present with ${value.split(";").length} directives` };
    },
  },
  {
    header: "X-Frame-Options",
    evaluate(value) {
      if (!value) return { status: "missing", detail: "X-Frame-Options not set" };
      const upper = value.toUpperCase();
      if (upper === "DENY" || upper === "SAMEORIGIN") return { status: "pass", detail: `X-Frame-Options: ${value}` };
      return { status: "fail", detail: `Unexpected X-Frame-Options value: ${value}` };
    },
  },
  {
    header: "X-Content-Type-Options",
    evaluate(value) {
      if (!value) return { status: "missing", detail: "X-Content-Type-Options not set" };
      if (value.toLowerCase() === "nosniff") return { status: "pass", detail: "nosniff set" };
      return { status: "fail", detail: `Unexpected value: ${value}` };
    },
  },
  {
    header: "Referrer-Policy",
    evaluate(value) {
      if (!value) return { status: "missing", detail: "Referrer-Policy not set" };
      return { status: "pass", detail: `Referrer-Policy: ${value}` };
    },
  },
  {
    header: "Permissions-Policy",
    evaluate(value) {
      if (!value) return { status: "missing", detail: "Permissions-Policy not set" };
      return { status: "pass", detail: "Permissions-Policy present" };
    },
  },
  {
    header: "Server",
    evaluate(value) {
      if (!value) return { status: "pass", detail: "Server header not exposed" };
      // Detailed server headers are an information leak
      if (value.includes("/")) return { status: "fail", detail: `Server header reveals version: ${value}` };
      return { status: "pass", detail: `Server header present but minimal: ${value}` };
    },
  },
];

function parseHeaders(raw: string): Map<string, string> {
  const headers = new Map<string, string>();
  for (const line of raw.split("\n")) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const name = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).trim();
    if (name) headers.set(name.toLowerCase(), value);
  }
  return headers;
}

function parseStatusCode(raw: string): number {
  // HTTP/1.1 200 OK or HTTP/2 200
  const match = raw.match(/^HTTP\/[\d.]+ (\d+)/m);
  return match ? parseInt(match[1], 10) : 0;
}

function scoreToGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}

export function scanHeaders(domain: string): HeadersRecon {
  const url = `https://${domain}`;
  const result = run("curl", ["-sI", "-L", "--max-time", "10", url], 15_000);

  if (result.exitCode !== 0 && !result.stdout) {
    return {
      domain,
      url,
      statusCode: 0,
      headers: SECURITY_HEADERS.map((spec) => ({
        header: spec.header,
        present: false,
        value: null,
        status: "missing" as const,
        detail: "Could not connect to host",
      })),
      score: 0,
      grade: "F",
    };
  }

  const rawHeaders = parseHeaders(result.stdout);
  const statusCode = parseStatusCode(result.stdout);

  const checks: HeaderCheck[] = [];
  let passCount = 0;

  for (const spec of SECURITY_HEADERS) {
    const headerLower = spec.header.toLowerCase();
    const value = rawHeaders.get(headerLower) ?? null;
    const { status, detail } = spec.evaluate(value);

    if (status === "pass") passCount++;

    checks.push({
      header: spec.header,
      present: value !== null,
      value,
      status,
      detail,
    });
  }

  // Score: each header worth roughly equal portion of 100
  // Server header is inverted (pass = not leaking), so all 7 headers contribute equally
  const score = Math.round((passCount / SECURITY_HEADERS.length) * 100);

  return {
    domain,
    url,
    statusCode,
    headers: checks,
    score,
    grade: scoreToGrade(score),
  };
}
