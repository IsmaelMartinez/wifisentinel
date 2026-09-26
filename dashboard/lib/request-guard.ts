// Pure request checks used by `proxy.ts` to keep the dashboard local-only.
// Kept free of Next.js imports so the root test suite can exercise it.

const LOCAL_HOSTNAMES = ["localhost", "127.0.0.1", "[::1]"];

export interface GuardInput {
  method: string;
  pathname: string;
  host: string | null;
  origin: string | null;
  contentType: string | null;
  port: string;
}

export type GuardResult = { ok: true } | { ok: false; reason: string };

export function allowedHosts(port: string): Set<string> {
  return new Set(LOCAL_HOSTNAMES.map((hostname) => `${hostname}:${port}`));
}

function mediaType(contentType: string): string {
  return contentType.split(";")[0].trim().toLowerCase();
}

export function checkRequest(input: GuardInput): GuardResult {
  const host = input.host?.toLowerCase() ?? null;
  if (host === null || !allowedHosts(input.port).has(host)) {
    return { ok: false, reason: "Host not allowed" };
  }

  const method = input.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD" && input.origin !== `http://${host}`) {
    return { ok: false, reason: "Cross-origin request not allowed" };
  }

  if (
    method === "POST" &&
    input.pathname === "/api/scans/run" &&
    (input.contentType === null || mediaType(input.contentType) !== "application/json")
  ) {
    return { ok: false, reason: "Content-Type must be application/json" };
  }

  return { ok: true };
}
