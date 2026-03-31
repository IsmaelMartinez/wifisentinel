# Phase 3a: Core Dashboard — Design Spec

## Overview

A Next.js App Router dashboard at `dashboard/` within the existing monorepo. Reads scan data from the `~/.wifisentinel/` store via API Route Handlers that import the existing store module. Dark theme with shadcn/ui and Geist font. Read-only — scans are created by the CLI, the dashboard visualises them.

## Project Structure

The dashboard lives at `dashboard/` with its own `package.json`, `tsconfig.json`, and `next.config.ts`. It imports shared types from the parent project via TypeScript path aliases (`@wifisentinel/` maps to `../src/`). The root `package.json` gets a `"dashboard": "cd dashboard && npx next dev"` script.

Dependencies: `next`, `react`, `react-dom`, `recharts` (charts), `tailwindcss`, plus shadcn/ui components installed via `npx shadcn@latest init`. No database — the JSON files are the data source.

## Data Layer

API Route Handlers in `dashboard/app/api/` that import the store module directly:

`GET /api/scans` — returns the scan index. Query params: `limit` (default 50), `ssid` (filter). Response: `IndexEntry[]`.

`GET /api/scans/[id]` — returns a full `StoredScan` by scan ID (full UUID or 8-char prefix). 404 if not found.

`GET /api/scans/[id]/rf` — returns the `RFAnalysis` for a scan. Recomputes from scan data if `rfAnalysis` is not present in the stored file (for scans saved before Phase 4).

All endpoints return JSON. No authentication — this is a local tool.

## Pages

### `/` — Overview

The landing page shows a snapshot of the most recent scan. Layout:

Top section: large security score gauge (0-10, colour-coded), compliance grade letter, consensus risk badge, SSID, and scan timestamp.

Middle section: five persona risk badges in a row (Red Team, Blue Team, Compliance, Net Engineer, Privacy) each showing their risk level with colour.

Bottom section: a sparkline chart showing the security score trend from the last 10 scans. Below that, a condensed RF summary — current channel saturation and rogue AP status.

Quick action links: "View Full Report" (to `/scans/[id]`), "History" (to `/scans`), "Trends" (to `/trends`).

If no scans exist, shows an empty state with instructions to run `wifisentinel scan`.

### `/scans` — History

A data table listing all stored scans. Columns: Date, SSID, Score, Grade, Risk, Hosts. Sortable by any column. Filterable by SSID via a dropdown. Each row is clickable and navigates to `/scans/[id]`.

Uses shadcn/ui Table component.

### `/scans/[id]` — Scan Detail

Full scan report with a tabbed layout (shadcn/ui Tabs):

**Summary tab**: network information (IP, subnet, gateway, topology), WiFi details (SSID, protocol, channel, band, signal/noise/SNR), security posture (firewall, VPN, proxy, kernel params), exposed services, connections summary, speed test results, and the security scorecard.

**Personas tab**: five expandable cards, one per persona. Each shows the persona name, risk rating, executive summary, and a list of insights with severity, description, technical detail, recommendation, and affected assets. Priority actions shown at the top.

**Compliance tab**: overall grade and score bar. Then a card per standard (CIS Wireless, NIST 800-153, IEEE 802.11, OWASP IoT) showing grade, score, and a list of findings with pass/fail/partial status, severity, description, and recommendation.

**RF tab**: channel saturation bar chart (Recharts BarChart, one bar per channel, coloured by saturation severity, current channel highlighted). Recommended channel callout. Rogue AP findings list (or "clear" badge). Environment changes section if the scan has a predecessor in history.

### `/trends` — Trends

Interactive line charts (Recharts) showing metrics over time across all stored scans:

- Security score (0-10)
- Compliance score (0-100%)
- Host count
- WiFi signal strength (dBm)
- SNR (dB)
- Nearby AP count

Each chart is a card with title and the line chart. Time axis is the scan timestamp. Hoverable tooltips show exact values. SSID filter dropdown to focus on a specific network.

## UI Components

Built on shadcn/ui (dark mode, zinc palette, Geist Sans/Mono):

`ScoreGauge` — circular/radial score display for the 0-10 security score. Colour transitions: green (8-10), yellow (5-7.9), red (0-4.9).

`RiskBadge` — small coloured badge showing a risk level. Uses shadcn Badge variant with custom colours: critical=red, high=red, medium=yellow, low=green, minimal=green.

`GradeBadge` — letter grade display (A-F) with colour coding.

`PersonaCard` — collapsible card for a persona analysis. Shows name, risk badge, summary. Expands to show full insights.

`ComplianceCard` — card for a standards score. Shows name, grade, score bar, findings list.

`ChannelChart` — Recharts BarChart wrapper for channel saturation data. Highlights current channel.

`TrendChart` — Recharts LineChart wrapper with tooltip, responsive container.

`ScanTable` — shadcn Table with sortable columns for the history page.

`EmptyState` — friendly message when no data exists.

## Layout

App-wide layout with a sidebar navigation (shadcn Sidebar): Overview, History, Trends. Top bar shows "WiFi Sentinel" branding and the current SSID from the latest scan. Sidebar collapses on smaller screens.

## File Structure

```
dashboard/
  package.json
  tsconfig.json
  next.config.ts
  tailwind.config.ts
  app/
    layout.tsx            — root layout with sidebar, dark mode, Geist fonts
    page.tsx              — overview page
    scans/
      page.tsx            — history page
      [id]/
        page.tsx          — scan detail page
    trends/
      page.tsx            — trends page
    api/
      scans/
        route.ts          — GET list scans
        [id]/
          route.ts        — GET single scan
          rf/
            route.ts      — GET RF analysis
  components/
    ui/                   — shadcn/ui components (installed via CLI)
    score-gauge.tsx
    risk-badge.tsx
    grade-badge.tsx
    persona-card.tsx
    compliance-card.tsx
    channel-chart.tsx
    trend-chart.tsx
    scan-table.tsx
    sidebar-nav.tsx
    empty-state.tsx
  lib/
    store.ts              — thin wrapper importing from @wifisentinel/store
    utils.ts              — cn() helper from shadcn
```

## Dependencies

```json
{
  "dependencies": {
    "next": "^15",
    "react": "^19",
    "react-dom": "^19",
    "recharts": "^2",
    "class-variance-authority": "^0.7",
    "clsx": "^2",
    "tailwind-merge": "^2",
    "lucide-react": "^0.400"
  },
  "devDependencies": {
    "typescript": "^5.7",
    "@types/node": "^22",
    "@types/react": "^19",
    "@types/react-dom": "^19",
    "tailwindcss": "^3",
    "postcss": "^8",
    "autoprefixer": "^10"
  }
}
```

shadcn/ui components are installed via `npx shadcn@latest init` and `npx shadcn@latest add` (table, tabs, badge, card, sidebar, etc.).

## Out of Scope

- PDF/HTML report generation (Phase 3b).
- Authentication / multi-user (local tool).
- Real-time WebSocket updates (polling or manual refresh is sufficient).
- Deployment to Vercel (local-only for now, though the architecture is compatible).
- Write operations (scans are created by the CLI only).
