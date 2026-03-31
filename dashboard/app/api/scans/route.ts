import { NextRequest, NextResponse } from "next/server";
import { getScans } from "@/lib/store";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const limit = parseInt(searchParams.get("limit") ?? "50", 10);
  const ssid = searchParams.get("ssid") ?? undefined;

  const scans = getScans({ limit, ssid });
  return NextResponse.json(scans);
}
