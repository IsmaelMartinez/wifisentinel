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
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
}
