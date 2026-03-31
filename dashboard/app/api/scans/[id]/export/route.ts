import { NextRequest, NextResponse } from "next/server";
import { getScan } from "@/lib/store";
import { renderHtmlReport } from "@wifisentinel/reporter/html.reporter.js";
import { analyseRF } from "@wifisentinel/analyser/rf/index.js";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const stored = getScan(id);
    if (!stored.rfAnalysis) {
      stored.rfAnalysis = analyseRF(stored.scan);
    }
    const html = renderHtmlReport(stored);
    const date = stored.scan.meta.timestamp.split("T")[0];

    return new NextResponse(html, {
      headers: {
        "Content-Type": "text/html",
        "Content-Disposition": `attachment; filename="wifisentinel-report-${date}.html"`,
      },
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 404 });
  }
}
