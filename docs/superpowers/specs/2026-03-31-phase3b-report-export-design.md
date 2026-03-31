# Phase 3b: HTML Report Export — Design Spec

## Overview

Add HTML report generation to WiFi Sentinel, accessible from both the CLI (`wifisentinel export`) and the dashboard (download button on scan detail page). Produces a self-contained HTML document with inline CSS — no external dependencies, opens in any browser, print-to-PDF friendly.

## Shared Report Renderer

### Location: `src/reporter/html.reporter.ts`

A function `renderHtmlReport(stored: StoredScan): string` that produces a complete HTML document. The report includes all scan data in a readable format:

- Header: scan ID, timestamp, hostname, platform, SSID, network info.
- Security Scorecard: score gauge (CSS-based circular gauge), risk label.
- Network Map: gateway, hosts table with IPs, MACs, vendors, ports.
- WiFi Details: protocol, channel, band, signal/noise/SNR, tx rate, nearby networks table.
- RF Intelligence: channel saturation table with bar indicators, recommended channel, rogue AP findings.
- Security Posture: firewall, VPN, proxy, kernel params, client isolation.
- DNS Audit: servers, DNSSEC, DoH/DoT, hijack test.
- Connections: established/listening/time_wait counts, top destinations.
- Speed Test: download/upload, latency, jitter, packet loss (if available).
- Persona Analyses: all five personas with risk rating, executive summary, insights, and priority actions.
- Compliance: overall grade and score, per-standard scores with findings (pass/fail/partial).

### Styling

Dark theme with inline CSS in a `<style>` block within the HTML `<head>`. Uses system fonts (no Geist dependency). Colour scheme matches the dashboard: zinc/neutral background, green/yellow/red for scores and severities. Print media query switches to light background for clean printing.

The HTML is fully self-contained — no external stylesheets, no JavaScript, no images. Just HTML + inline CSS. This means the file can be emailed, uploaded, archived, or opened offline.

### Score Rendering

The security score gauge is rendered as a CSS-only circular element using `conic-gradient`. Compliance score bars use simple `<div>` elements with percentage widths. Severity indicators use coloured text spans.

## CLI Command

### `wifisentinel export <scanId>`

Loads a stored scan from the Phase 2 store and writes the HTML report to a file.

Options:
- `-o, --output <path>`: output file path. Default: `wifisentinel-report-<YYYY-MM-DD>.html` in the current directory.
- `--stdout`: write to stdout instead of a file (for piping).

The scan ID accepts full UUIDs or 8-character prefixes (same as `diff` and `rf --compare`).

If the scan has no `rfAnalysis` stored, it is recomputed from the scan data before rendering.

### File: `src/commands/export.ts`

Registers the `export` command with commander, calls `loadScan`, optionally recomputes RF analysis, calls `renderHtmlReport`, writes output.

## Dashboard Integration

### Export Button

An "Export HTML" link/button on the scan detail page (`dashboard/app/scans/[id]/page.tsx`), positioned next to the scan header. Links to `/api/scans/[id]/export`.

### API Route

`GET /api/scans/[id]/export` — returns the HTML report as a downloadable file.

File: `dashboard/app/api/scans/[id]/export/route.ts`

Response headers:
- `Content-Type: text/html`
- `Content-Disposition: attachment; filename="wifisentinel-report-<date>.html"`

The route imports the shared `renderHtmlReport` from the parent project (via the `@wifisentinel/` path alias), loads the scan from the store, and returns the HTML.

## File Structure

New files:

```
src/
  reporter/
    html.reporter.ts    — renderHtmlReport(stored) -> string
  commands/
    export.ts           — export CLI command handler

dashboard/
  app/
    api/
      scans/
        [id]/
          export/
            route.ts    — GET download endpoint
```

Modified files:

```
src/cli.ts                          — register export command
dashboard/app/scans/[id]/page.tsx   — add Export HTML button
```

## Dependencies

No new dependencies. The HTML is built with template literals and inline CSS. The CLI command uses the existing store module and commander.

## Out of Scope

- Native PDF generation (users can print-to-PDF from their browser).
- Custom branding / logo support.
- Template customisation.
- Batch export of multiple scans.
