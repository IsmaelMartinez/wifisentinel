import { NextRequest, NextResponse } from "next/server";
import { getScan } from "@/lib/store";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const scan = getScan(id);
    return NextResponse.json(scan);
  } catch {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
}
