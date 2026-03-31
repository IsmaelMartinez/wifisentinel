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
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 404 });
  }
}
