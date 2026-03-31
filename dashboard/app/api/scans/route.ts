import { NextRequest, NextResponse } from "next/server";
import { getScans } from "@/lib/store";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const rawLimit = parseInt(searchParams.get("limit") ?? "50", 10);
  const limit = Number.isNaN(rawLimit) ? 50 : Math.min(Math.max(1, rawLimit), 200);
  const ssid = searchParams.get("ssid") ?? undefined;

  const scans = getScans({ limit, ssid });
  return NextResponse.json(scans);
}
