import { NextResponse, type NextRequest } from "next/server";
import { checkRequest } from "@/lib/request-guard";

// Only same-origin requests to a localhost Host may reach the dashboard.
// This blocks cross-site form/no-cors POSTs to /api/scans/run and DNS
// rebinding reads of the scan store.
export function proxy(request: NextRequest) {
  const result = checkRequest({
    method: request.method,
    pathname: request.nextUrl.pathname,
    host: request.headers.get("host"),
    origin: request.headers.get("origin"),
    contentType: request.headers.get("content-type"),
    port: process.env.PORT ?? "3000",
  });

  if (!result.ok) {
    return NextResponse.json({ error: result.reason }, { status: 403 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
