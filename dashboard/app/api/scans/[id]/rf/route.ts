import { NextRequest, NextResponse } from "next/server";
import { getRFAnalysis } from "@/lib/store";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const rf = getRFAnalysis(id);
    return NextResponse.json(rf);
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 404 });
  }
}
