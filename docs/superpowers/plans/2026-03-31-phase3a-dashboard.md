# Phase 3a: Core Dashboard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Next.js dashboard that visualises WiFi Sentinel scan data with persona perspectives, compliance tracking, RF channel maps, and historical trends.

**Architecture:** Next.js App Router at `dashboard/` in the monorepo. Server-side API routes read from `~/.wifisentinel/` JSON store. Dark theme with shadcn/ui, Recharts for charts. Imports shared types from parent project via path aliases.

**Tech Stack:** Next.js 15, React 19, shadcn/ui, Tailwind CSS, Recharts, TypeScript.

---

### Task 1: Scaffold the Next.js dashboard project

**Files:**
- Create: `dashboard/package.json`
- Create: `dashboard/tsconfig.json`
- Create: `dashboard/next.config.ts`
- Create: `dashboard/postcss.config.mjs`
- Create: `dashboard/tailwind.config.ts`
- Create: `dashboard/app/globals.css`
- Create: `dashboard/app/layout.tsx`
- Create: `dashboard/app/page.tsx`
- Create: `dashboard/lib/utils.ts`
- Create: `dashboard/components.json`
- Modify: `package.json` (root)

- [ ] **Step 1: Create dashboard/package.json**

```json
{
  "name": "wifisentinel-dashboard",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "next": "^15.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "recharts": "^2.15.0",
    "class-variance-authority": "^0.7.1",
    "clsx": "^2.1.1",
    "tailwind-merge": "^2.6.0",
    "lucide-react": "^0.468.0",
    "zod": "^3.24.0"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "@types/node": "^22.13.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "tailwindcss": "^3.4.0",
    "postcss": "^8.4.0",
    "autoprefixer": "^10.4.0"
  }
}
```

- [ ] **Step 2: Create dashboard/tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "ES2022"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [{ "name": "next" }],
    "paths": {
      "@/*": ["./*"],
      "@wifisentinel/*": ["../src/*"]
    }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

- [ ] **Step 3: Create dashboard/next.config.ts**

```ts
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["../src"],
  serverExternalPackages: ["zod"],
};

export default nextConfig;
```

- [ ] **Step 4: Create dashboard/postcss.config.mjs**

```js
/** @type {import('postcss-load-config').Config} */
const config = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
export default config;
```

- [ ] **Step 5: Create dashboard/tailwind.config.ts**

```ts
import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-geist-sans)"],
        mono: ["var(--font-geist-mono)"],
      },
    },
  },
  plugins: [],
};
export default config;
```

- [ ] **Step 6: Create dashboard/app/globals.css**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 240 10% 3.9%;
    --card: 0 0% 100%;
    --card-foreground: 240 10% 3.9%;
    --popover: 0 0% 100%;
    --popover-foreground: 240 10% 3.9%;
    --primary: 240 5.9% 10%;
    --primary-foreground: 0 0% 98%;
    --secondary: 240 4.8% 95.9%;
    --secondary-foreground: 240 5.9% 10%;
    --muted: 240 4.8% 95.9%;
    --muted-foreground: 240 3.8% 46.1%;
    --accent: 240 4.8% 95.9%;
    --accent-foreground: 240 5.9% 10%;
    --destructive: 0 84.2% 60.2%;
    --destructive-foreground: 0 0% 98%;
    --border: 240 5.9% 90%;
    --input: 240 5.9% 90%;
    --ring: 240 5.9% 10%;
    --radius: 0.5rem;
  }

  .dark {
    --background: 240 10% 3.9%;
    --foreground: 0 0% 98%;
    --card: 240 10% 3.9%;
    --card-foreground: 0 0% 98%;
    --popover: 240 10% 3.9%;
    --popover-foreground: 0 0% 98%;
    --primary: 0 0% 98%;
    --primary-foreground: 240 5.9% 10%;
    --secondary: 240 3.7% 15.9%;
    --secondary-foreground: 0 0% 98%;
    --muted: 240 3.7% 15.9%;
    --muted-foreground: 240 5% 64.9%;
    --accent: 240 3.7% 15.9%;
    --accent-foreground: 0 0% 98%;
    --destructive: 0 62.8% 30.6%;
    --destructive-foreground: 0 0% 98%;
    --border: 240 3.7% 15.9%;
    --input: 240 3.7% 15.9%;
    --ring: 240 4.9% 83.9%;
  }
}

@layer base {
  * {
    @apply border-border;
  }
  body {
    @apply bg-background text-foreground;
  }
}
```

- [ ] **Step 7: Create dashboard/lib/utils.ts**

```ts
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
```

- [ ] **Step 8: Create dashboard/components.json**

```json
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "default",
  "rsc": true,
  "tsx": true,
  "tailwind": {
    "config": "tailwind.config.ts",
    "css": "app/globals.css",
    "baseColor": "zinc",
    "cssVariables": true
  },
  "aliases": {
    "components": "@/components",
    "utils": "@/lib/utils",
    "ui": "@/components/ui",
    "lib": "@/lib"
  }
}
```

- [ ] **Step 9: Create dashboard/app/layout.tsx**

```tsx
import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";

export const metadata: Metadata = {
  title: "WiFi Sentinel",
  description: "Network security dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${GeistSans.variable} ${GeistMono.variable} font-sans antialiased`}>
        {children}
      </body>
    </html>
  );
}
```

- [ ] **Step 10: Create dashboard/app/page.tsx (placeholder)**

```tsx
export default function Home() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold">WiFi Sentinel</h1>
        <p className="mt-2 text-muted-foreground">Dashboard loading...</p>
      </div>
    </div>
  );
}
```

- [ ] **Step 11: Add dashboard script to root package.json**

In the root `/Users/ismael.martinez/projects/github/wifisentinel/package.json`, add to the `"scripts"` section:

```json
"dashboard": "cd dashboard && npx next dev"
```

- [ ] **Step 12: Install dependencies**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npm install
```

Install geist font:
```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npm install geist
```

- [ ] **Step 13: Add dashboard/node_modules and .next to .gitignore**

Create `dashboard/.gitignore`:

```
node_modules
.next
```

- [ ] **Step 14: Verify the dev server starts**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npx next dev --port 3100 &
sleep 5 && curl -s http://localhost:3100 | head -20
kill %1 2>/dev/null
```

Expected: HTML response containing "WiFi Sentinel".

- [ ] **Step 15: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/ package.json
git commit -m "scaffold Next.js dashboard project with Tailwind and dark theme"
```

---

### Task 2: Store wrapper and API routes

**Files:**
- Create: `dashboard/lib/store.ts`
- Create: `dashboard/app/api/scans/route.ts`
- Create: `dashboard/app/api/scans/[id]/route.ts`
- Create: `dashboard/app/api/scans/[id]/rf/route.ts`

- [ ] **Step 1: Create the store wrapper**

```ts
// dashboard/lib/store.ts
import { listScans, loadScan, type IndexEntry, type StoredScan } from "@wifisentinel/store/index.js";
import { analyseRF, type RFAnalysis } from "@wifisentinel/analyser/rf/index.js";

export type { IndexEntry, StoredScan };
export type { RFAnalysis };

export function getScans(options?: { limit?: number; ssid?: string }): IndexEntry[] {
  return listScans(options);
}

export function getScan(id: string): StoredScan {
  return loadScan(id);
}

export function getRFAnalysis(id: string): RFAnalysis {
  const stored = loadScan(id);
  if (stored.rfAnalysis) return stored.rfAnalysis;
  // Recompute for scans saved before Phase 4
  return analyseRF(stored.scan);
}
```

- [ ] **Step 2: Create GET /api/scans**

```ts
// dashboard/app/api/scans/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getScans } from "@/lib/store";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const limit = parseInt(searchParams.get("limit") ?? "50", 10);
  const ssid = searchParams.get("ssid") ?? undefined;

  const scans = getScans({ limit, ssid });
  return NextResponse.json(scans);
}
```

- [ ] **Step 3: Create GET /api/scans/[id]**

```ts
// dashboard/app/api/scans/[id]/route.ts
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
```

- [ ] **Step 4: Create GET /api/scans/[id]/rf**

```ts
// dashboard/app/api/scans/[id]/rf/route.ts
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
```

- [ ] **Step 5: Test the API**

Start the dev server and test:
```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npx next dev --port 3100 &
sleep 5
curl -s http://localhost:3100/api/scans | head -50
kill %1 2>/dev/null
```

Expected: JSON array of scan index entries.

If the import from `@wifisentinel/` fails, you may need to adjust `next.config.ts` to handle the path alias. Try adding `webpack` config:

```ts
import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  transpilePackages: ["../src"],
  serverExternalPackages: ["zod"],
  webpack: (config) => {
    config.resolve.alias["@wifisentinel"] = path.resolve(__dirname, "../src");
    return config;
  },
};

export default nextConfig;
```

- [ ] **Step 6: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/lib/store.ts dashboard/app/api/
git commit -m "add API routes for scan data access"
```

---

### Task 3: Install shadcn/ui components and create shared UI components

**Files:**
- Create: `dashboard/components/score-gauge.tsx`
- Create: `dashboard/components/risk-badge.tsx`
- Create: `dashboard/components/grade-badge.tsx`
- Create: `dashboard/components/empty-state.tsx`

- [ ] **Step 1: Install shadcn/ui components**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard
npx shadcn@latest add card badge tabs table
```

This creates files in `dashboard/components/ui/`.

- [ ] **Step 2: Create ScoreGauge component**

```tsx
// dashboard/components/score-gauge.tsx
import { cn } from "@/lib/utils";

function scoreColor(score: number): string {
  if (score >= 8) return "text-green-500";
  if (score >= 5) return "text-yellow-500";
  return "text-red-500";
}

function scoreBgRing(score: number): string {
  if (score >= 8) return "stroke-green-500/20";
  if (score >= 5) return "stroke-yellow-500/20";
  return "stroke-red-500/20";
}

function scoreRing(score: number): string {
  if (score >= 8) return "stroke-green-500";
  if (score >= 5) return "stroke-yellow-500";
  return "stroke-red-500";
}

export function ScoreGauge({ score, size = 120 }: { score: number; size?: number }) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 10) * circumference;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" className="transform -rotate-90" style={{ width: size, height: size }}>
        <circle cx="50" cy="50" r={radius} fill="none" strokeWidth="8" className={scoreBgRing(score)} />
        <circle
          cx="50" cy="50" r={radius} fill="none" strokeWidth="8"
          className={scoreRing(score)}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("text-3xl font-bold", scoreColor(score))}>{score.toFixed(1)}</span>
        <span className="text-xs text-muted-foreground">/10</span>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Create RiskBadge component**

```tsx
// dashboard/components/risk-badge.tsx
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const riskStyles: Record<string, string> = {
  critical: "bg-red-600 text-white hover:bg-red-600",
  high: "bg-red-500/20 text-red-400 hover:bg-red-500/20",
  medium: "bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/20",
  low: "bg-green-500/20 text-green-400 hover:bg-green-500/20",
  minimal: "bg-green-500/10 text-green-500 hover:bg-green-500/10",
};

export function RiskBadge({ risk, className }: { risk: string; className?: string }) {
  return (
    <Badge variant="secondary" className={cn(riskStyles[risk] ?? riskStyles.minimal, className)}>
      {risk.toUpperCase()}
    </Badge>
  );
}
```

- [ ] **Step 4: Create GradeBadge component**

```tsx
// dashboard/components/grade-badge.tsx
import { cn } from "@/lib/utils";

function gradeColor(grade: string): string {
  if (grade === "A" || grade === "B") return "text-green-400 border-green-400/30";
  if (grade === "C" || grade === "D") return "text-yellow-400 border-yellow-400/30";
  return "text-red-400 border-red-400/30";
}

export function GradeBadge({ grade, className }: { grade: string; className?: string }) {
  return (
    <span className={cn(
      "inline-flex items-center justify-center w-10 h-10 rounded-lg border-2 text-xl font-bold font-mono",
      gradeColor(grade),
      className,
    )}>
      {grade}
    </span>
  );
}
```

- [ ] **Step 5: Create EmptyState component**

```tsx
// dashboard/components/empty-state.tsx
import { Wifi } from "lucide-react";

export function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <Wifi className="h-16 w-16 text-muted-foreground/30 mb-4" />
      <h2 className="text-xl font-semibold">No scans found</h2>
      <p className="mt-2 text-muted-foreground max-w-sm">
        Run <code className="px-1.5 py-0.5 rounded bg-muted font-mono text-sm">wifisentinel scan</code> in
        your terminal to record your first network scan.
      </p>
    </div>
  );
}
```

- [ ] **Step 6: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/components/
git commit -m "add shadcn/ui components and shared score/risk/grade badges"
```

---

### Task 4: Layout with sidebar navigation

**Files:**
- Create: `dashboard/components/sidebar-nav.tsx`
- Modify: `dashboard/app/layout.tsx`

- [ ] **Step 1: Create SidebarNav component**

```tsx
// dashboard/components/sidebar-nav.tsx
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, History, TrendingUp, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/scans", label: "History", icon: History },
  { href: "/trends", label: "Trends", icon: TrendingUp },
];

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 z-10 flex w-56 flex-col border-r border-border bg-card">
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <Shield className="h-5 w-5 text-primary" />
        <span className="font-semibold">WiFi Sentinel</span>
      </div>
      <nav className="flex-1 space-y-1 p-2">
        {navItems.map((item) => {
          const isActive = item.href === "/"
            ? pathname === "/"
            : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-accent text-accent-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
```

- [ ] **Step 2: Update layout.tsx**

Replace `dashboard/app/layout.tsx` with:

```tsx
import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { SidebarNav } from "@/components/sidebar-nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "WiFi Sentinel",
  description: "Network security dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${GeistSans.variable} ${GeistMono.variable} font-sans antialiased`}>
        <SidebarNav />
        <main className="ml-56 min-h-screen p-6">
          {children}
        </main>
      </body>
    </html>
  );
}
```

- [ ] **Step 3: Verify sidebar renders**

Start dev server, check visually or curl:
```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npx next dev --port 3100 &
sleep 5 && curl -s http://localhost:3100 | grep -o "WiFi Sentinel"
kill %1 2>/dev/null
```

Expected: "WiFi Sentinel" in output.

- [ ] **Step 4: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/components/sidebar-nav.tsx dashboard/app/layout.tsx
git commit -m "add sidebar navigation layout"
```

---

### Task 5: Overview page

**Files:**
- Modify: `dashboard/app/page.tsx`

- [ ] **Step 1: Build the overview page**

```tsx
// dashboard/app/page.tsx
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScoreGauge } from "@/components/score-gauge";
import { RiskBadge } from "@/components/risk-badge";
import { GradeBadge } from "@/components/grade-badge";
import { EmptyState } from "@/components/empty-state";
import { getScans, getScan } from "@/lib/store";

const personaNames: Record<string, string> = {
  "red-team": "Red Team",
  "blue-team": "Blue Team",
  "compliance": "Compliance",
  "net-engineer": "Net Engineer",
  "privacy": "Privacy",
};

export const dynamic = "force-dynamic";

export default function OverviewPage() {
  const entries = getScans({ limit: 10 });

  if (entries.length === 0) {
    return <EmptyState />;
  }

  const latest = entries[0];
  let stored;
  try {
    stored = getScan(latest.scanId);
  } catch {
    return <EmptyState />;
  }

  const { scan, analysis, compliance } = stored;
  const rfSummary = stored.rfAnalysis;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Overview</h1>
          <p className="text-sm text-muted-foreground">
            {scan.wifi.ssid ?? "(hidden)"} &middot; {new Date(scan.meta.timestamp).toLocaleString()}
          </p>
        </div>
        <Link
          href={`/scans/${latest.scanId}`}
          className="text-sm text-primary hover:underline"
        >
          View Full Report
        </Link>
      </div>

      {/* Top metrics */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="flex flex-col items-center pt-6">
            <ScoreGauge score={latest.securityScore} />
            <p className="mt-2 text-sm text-muted-foreground">Security Score</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-col items-center justify-center pt-6">
            <GradeBadge grade={latest.complianceGrade} />
            <p className="mt-3 text-sm text-muted-foreground">Compliance</p>
            <p className="text-xs text-muted-foreground">{compliance.overallScore}%</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-col items-center justify-center pt-6">
            <RiskBadge risk={latest.consensusRisk} className="text-lg px-4 py-1" />
            <p className="mt-3 text-sm text-muted-foreground">Consensus Risk</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-col items-center justify-center pt-6">
            <span className="text-3xl font-bold">{latest.hostCount}</span>
            <p className="mt-2 text-sm text-muted-foreground">Hosts</p>
          </CardContent>
        </Card>
      </div>

      {/* Persona badges */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Persona Risk Assessment</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            {analysis.analyses.map((a) => (
              <div key={a.persona} className="flex flex-col items-center gap-1.5">
                <RiskBadge risk={a.riskRating} />
                <span className="text-xs text-muted-foreground">
                  {personaNames[a.persona] ?? a.persona}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Score trend + RF summary */}
      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Score Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-16">
              {[...entries].reverse().map((e) => {
                const height = Math.max(4, (e.securityScore / 10) * 64);
                const color = e.securityScore >= 8 ? "bg-green-500" : e.securityScore >= 5 ? "bg-yellow-500" : "bg-red-500";
                return (
                  <div
                    key={e.scanId}
                    className={`${color} rounded-sm flex-1 min-w-1`}
                    style={{ height }}
                    title={`${e.securityScore.toFixed(1)} — ${new Date(e.timestamp).toLocaleDateString()}`}
                  />
                );
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">RF Summary</CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-1">
            {rfSummary ? (
              <>
                <p>
                  Channel {rfSummary.channelMap.currentChannel} &middot;
                  Saturation: <span className={
                    rfSummary.channelMap.currentSaturation <= 30 ? "text-green-400" :
                    rfSummary.channelMap.currentSaturation <= 60 ? "text-yellow-400" : "text-red-400"
                  }>{rfSummary.channelMap.currentSaturation}%</span>
                </p>
                {rfSummary.channelMap.recommendedChannel !== rfSummary.channelMap.currentChannel && (
                  <p className="text-yellow-400">
                    Consider channel {rfSummary.channelMap.recommendedChannel}
                  </p>
                )}
                <p>
                  Rogue APs: <span className={
                    rfSummary.rogueAPs.riskLevel === "clear" ? "text-green-400" : "text-red-400"
                  }>{rfSummary.rogueAPs.riskLevel}</span>
                </p>
              </>
            ) : (
              <p className="text-muted-foreground">No RF data available</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Quick links */}
      <div className="flex gap-4">
        <Link href="/scans" className="text-sm text-primary hover:underline">
          View History
        </Link>
        <Link href="/trends" className="text-sm text-primary hover:underline">
          View Trends
        </Link>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Test overview page loads**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npx next dev --port 3100 &
sleep 5 && curl -s http://localhost:3100 | grep -o "Security Score\|Compliance\|Consensus Risk"
kill %1 2>/dev/null
```

Expected: "Security Score", "Compliance", "Consensus Risk" all found.

- [ ] **Step 3: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/app/page.tsx
git commit -m "add overview page with score gauge, persona badges, and RF summary"
```

---

### Task 6: History page with scan table

**Files:**
- Create: `dashboard/components/scan-table.tsx`
- Create: `dashboard/app/scans/page.tsx`

- [ ] **Step 1: Create ScanTable component**

```tsx
// dashboard/components/scan-table.tsx
"use client";

import { useRouter } from "next/navigation";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { RiskBadge } from "@/components/risk-badge";
import { GradeBadge } from "@/components/grade-badge";
import type { IndexEntry } from "@/lib/store";

export function ScanTable({ entries }: { entries: IndexEntry[] }) {
  const router = useRouter();

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Date</TableHead>
          <TableHead>SSID</TableHead>
          <TableHead className="text-right">Score</TableHead>
          <TableHead className="text-center">Grade</TableHead>
          <TableHead className="text-center">Risk</TableHead>
          <TableHead className="text-right">Hosts</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {entries.map((e) => (
          <TableRow
            key={e.scanId}
            className="cursor-pointer"
            onClick={() => router.push(`/scans/${e.scanId}`)}
          >
            <TableCell className="font-mono text-sm">
              {new Date(e.timestamp).toLocaleString("en-GB", {
                year: "numeric", month: "2-digit", day: "2-digit",
                hour: "2-digit", minute: "2-digit",
              })}
            </TableCell>
            <TableCell>{e.ssid ?? <span className="text-muted-foreground">(hidden)</span>}</TableCell>
            <TableCell className="text-right font-mono">{e.securityScore.toFixed(1)}</TableCell>
            <TableCell className="text-center">
              <GradeBadge grade={e.complianceGrade} className="w-7 h-7 text-sm" />
            </TableCell>
            <TableCell className="text-center">
              <RiskBadge risk={e.consensusRisk} />
            </TableCell>
            <TableCell className="text-right">{e.hostCount}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
```

- [ ] **Step 2: Create the history page**

```tsx
// dashboard/app/scans/page.tsx
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanTable } from "@/components/scan-table";
import { EmptyState } from "@/components/empty-state";
import { getScans } from "@/lib/store";

export const dynamic = "force-dynamic";

export default function HistoryPage() {
  const entries = getScans({ limit: 100 });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Scan History</h1>
      {entries.length === 0 ? (
        <EmptyState />
      ) : (
        <Card>
          <CardContent className="pt-6">
            <ScanTable entries={entries} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/components/scan-table.tsx dashboard/app/scans/
git commit -m "add history page with sortable scan table"
```

---

### Task 7: Scan detail page with tabs

**Files:**
- Create: `dashboard/components/persona-card.tsx`
- Create: `dashboard/components/compliance-card.tsx`
- Create: `dashboard/components/channel-chart.tsx`
- Create: `dashboard/app/scans/[id]/page.tsx`

- [ ] **Step 1: Create PersonaCard component**

```tsx
// dashboard/components/persona-card.tsx
"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { RiskBadge } from "@/components/risk-badge";
import { ChevronDown, ChevronRight } from "lucide-react";

interface Insight {
  id: string;
  title: string;
  severity: string;
  description: string;
  technicalDetail: string;
  recommendation: string;
  affectedAssets: string[];
}

interface PersonaAnalysis {
  persona: string;
  displayName: string;
  riskRating: string;
  executiveSummary: string;
  insights: Insight[];
  priorityActions: string[];
}

const severityColor: Record<string, string> = {
  critical: "text-red-500",
  high: "text-red-400",
  medium: "text-yellow-400",
  low: "text-muted-foreground",
  info: "text-muted-foreground",
};

export function PersonaCard({ analysis }: { analysis: PersonaAnalysis }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardHeader
        className="cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            <CardTitle className="text-base">{analysis.displayName}</CardTitle>
            <RiskBadge risk={analysis.riskRating} />
          </div>
          <span className="text-sm text-muted-foreground">
            {analysis.insights.length} finding{analysis.insights.length !== 1 ? "s" : ""}
          </span>
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-4">
          <p className="text-sm">{analysis.executiveSummary}</p>

          {analysis.priorityActions.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold mb-1">Priority Actions</h4>
              {analysis.priorityActions.map((a, i) => (
                <p key={i} className="text-sm text-muted-foreground ml-2">
                  &rarr; {a}
                </p>
              ))}
            </div>
          )}

          {analysis.insights.map((insight) => (
            <div key={insight.id} className="border-l-2 border-border pl-3 space-y-1">
              <p className="text-sm">
                <span className={severityColor[insight.severity] ?? ""}>[{insight.severity.toUpperCase()}]</span>{" "}
                {insight.title}
              </p>
              <p className="text-xs text-muted-foreground">{insight.description}</p>
              <p className="text-xs font-mono text-muted-foreground">{insight.technicalDetail}</p>
              <p className="text-xs text-primary">&rarr; {insight.recommendation}</p>
            </div>
          ))}
        </CardContent>
      )}
    </Card>
  );
}
```

- [ ] **Step 2: Create ComplianceCard component**

```tsx
// dashboard/components/compliance-card.tsx
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { GradeBadge } from "@/components/grade-badge";

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  description: string;
  recommendation: string;
  evidence?: string;
}

interface StandardScore {
  standard: string;
  name: string;
  score: number;
  grade: string;
  findings: Finding[];
  summary: string;
}

const statusIcon: Record<string, string> = {
  pass: "text-green-400",
  fail: "text-red-400",
  partial: "text-yellow-400",
  "not-applicable": "text-muted-foreground",
};

const statusLabel: Record<string, string> = {
  pass: "\u2714",
  fail: "\u2718",
  partial: "\u25D0",
  "not-applicable": "\u2014",
};

export function ComplianceCard({ standard }: { standard: StandardScore }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <GradeBadge grade={standard.grade} className="w-8 h-8 text-base" />
            <div>
              <CardTitle className="text-base">{standard.name}</CardTitle>
              <p className="text-xs text-muted-foreground">{standard.summary}</p>
            </div>
          </div>
          <div className="text-right">
            <span className="text-2xl font-bold font-mono">{standard.score}%</span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="w-full bg-muted rounded-full h-2 mb-4">
          <div
            className={`h-2 rounded-full ${
              standard.score >= 80 ? "bg-green-500" : standard.score >= 60 ? "bg-yellow-500" : "bg-red-500"
            }`}
            style={{ width: `${standard.score}%` }}
          />
        </div>
        <div className="space-y-2">
          {standard.findings.map((f) => (
            <div key={f.id} className="flex items-start gap-2 text-sm">
              <span className={statusIcon[f.status] ?? ""}>{statusLabel[f.status] ?? "?"}</span>
              <div>
                <span className="text-muted-foreground">[{f.severity.toUpperCase()}]</span> {f.title}
                {f.status === "fail" && f.recommendation && (
                  <p className="text-xs text-primary mt-0.5">&rarr; {f.recommendation}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 3: Create ChannelChart component**

```tsx
// dashboard/components/channel-chart.tsx
"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer } from "recharts";

interface ChannelInfo {
  channel: number;
  saturationScore: number;
  networkCount: number;
  overlapCount: number;
}

function barColor(score: number, isCurrent: boolean): string {
  if (isCurrent) return "#3b82f6"; // blue for current
  if (score <= 30) return "#22c55e";
  if (score <= 60) return "#eab308";
  return "#ef4444";
}

export function ChannelChart({
  channels,
  currentChannel,
}: {
  channels: ChannelInfo[];
  currentChannel: number;
}) {
  const data = channels.map((ch) => ({
    name: `Ch ${ch.channel}`,
    saturation: ch.saturationScore,
    networks: ch.networkCount,
    overlap: ch.overlapCount,
    isCurrent: ch.channel === currentChannel,
  }));

  return (
    <ResponsiveContainer width="100%" height={250}>
      <BarChart data={data}>
        <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#a1a1aa" }} />
        <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "#a1a1aa" }} />
        <Tooltip
          contentStyle={{ backgroundColor: "#18181b", border: "1px solid #27272a", borderRadius: "8px" }}
          labelStyle={{ color: "#fafafa" }}
          formatter={(value: number, _name: string, props: any) => {
            const item = props.payload;
            return [`${value}% (${item.networks} direct, ${item.overlap} overlap)`, "Saturation"];
          }}
        />
        <Bar dataKey="saturation" radius={[4, 4, 0, 0]}>
          {data.map((entry, index) => (
            <Cell key={index} fill={barColor(entry.saturation, entry.isCurrent)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
```

- [ ] **Step 4: Create the scan detail page**

```tsx
// dashboard/app/scans/[id]/page.tsx
import { notFound } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScoreGauge } from "@/components/score-gauge";
import { RiskBadge } from "@/components/risk-badge";
import { GradeBadge } from "@/components/grade-badge";
import { PersonaCard } from "@/components/persona-card";
import { ComplianceCard } from "@/components/compliance-card";
import { ChannelChart } from "@/components/channel-chart";
import { getScan } from "@/lib/store";
import { computeSecurityScore } from "@wifisentinel/analyser/score.js";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let stored;
  try {
    stored = getScan(id);
  } catch {
    notFound();
  }

  const { scan, compliance, analysis, rfAnalysis } = stored;
  const score = computeSecurityScore(scan);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">
          Scan Report
        </h1>
        <p className="text-sm text-muted-foreground">
          {scan.wifi.ssid ?? "(hidden)"} &middot; {new Date(scan.meta.timestamp).toLocaleString()} &middot;
          ID: <span className="font-mono">{scan.meta.scanId.slice(0, 8)}</span>
        </p>
      </div>

      <Tabs defaultValue="summary">
        <TabsList>
          <TabsTrigger value="summary">Summary</TabsTrigger>
          <TabsTrigger value="personas">Personas</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="rf">RF</TabsTrigger>
        </TabsList>

        {/* Summary Tab */}
        <TabsContent value="summary" className="space-y-4 mt-4">
          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardContent className="flex flex-col items-center pt-6">
                <ScoreGauge score={score} />
                <p className="mt-2 text-sm text-muted-foreground">Security Score</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">Network</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>IP: <span className="font-mono">{scan.network.ip}</span></p>
                <p>Subnet: <span className="font-mono">{scan.network.subnet}</span></p>
                <p>Gateway: <span className="font-mono">{scan.network.gateway.ip}</span></p>
                {scan.network.gateway.vendor && <p className="text-muted-foreground">{scan.network.gateway.vendor}</p>}
                <p>Hosts: {scan.network.hosts.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">WiFi</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>Protocol: {scan.wifi.protocol}</p>
                <p>Channel: {scan.wifi.channel} ({scan.wifi.band}, {scan.wifi.width})</p>
                <p>Security: {scan.wifi.security}</p>
                <p>Signal: {scan.wifi.signal} dBm / SNR: {scan.wifi.snr} dB</p>
                <p>TX Rate: {scan.wifi.txRate} Mbps</p>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-base">Security Posture</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>Firewall: {scan.security.firewall.enabled ? "\u2714 Enabled" : "\u2718 Disabled"}
                  {scan.security.firewall.stealthMode ? " (stealth)" : ""}</p>
                <p>VPN: {scan.security.vpn.active ? "\u2714 Active" : "\u2718 Inactive"}
                  {scan.security.vpn.provider ? ` (${scan.security.vpn.provider})` : ""}</p>
                <p>Client Isolation: {scan.security.clientIsolation === true ? "\u2714" : scan.security.clientIsolation === false ? "\u2718" : "Unknown"}</p>
                <p>IP Forwarding: {scan.security.kernelParams.ipForwarding ? "\u2718 Enabled" : "\u2714 Disabled"}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">Connections</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-1">
                <p>Established: {scan.connections.established}</p>
                <p>Listening: {scan.connections.listening}</p>
                <p>TIME_WAIT: {scan.connections.timeWait}</p>
                {scan.speed && (
                  <>
                    <p className="mt-2">Download: {scan.speed.download.speedMbps} Mbps</p>
                    <p>Latency: {scan.speed.latency.internetMs} ms</p>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Personas Tab */}
        <TabsContent value="personas" className="space-y-4 mt-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm text-muted-foreground">Consensus:</span>
            <RiskBadge risk={analysis.consensusRating} />
          </div>
          {analysis.analyses.map((a) => (
            <PersonaCard key={a.persona} analysis={a} />
          ))}
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="space-y-4 mt-4">
          <div className="flex items-center gap-4 mb-2">
            <GradeBadge grade={compliance.overallGrade} />
            <div>
              <p className="font-semibold">Overall: {compliance.overallScore}%</p>
            </div>
          </div>
          {compliance.standards.map((s) => (
            <ComplianceCard key={s.standard} standard={s} />
          ))}
        </TabsContent>

        {/* RF Tab */}
        <TabsContent value="rf" className="space-y-4 mt-4">
          {rfAnalysis ? (
            <>
              <Card>
                <CardHeader><CardTitle className="text-base">Channel Saturation</CardTitle></CardHeader>
                <CardContent>
                  <ChannelChart
                    channels={rfAnalysis.channelMap.channels}
                    currentChannel={rfAnalysis.channelMap.currentChannel}
                  />
                  <p className="mt-2 text-sm text-muted-foreground">
                    {rfAnalysis.channelMap.recommendationReason}
                  </p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-base">Rogue AP Detection</CardTitle></CardHeader>
                <CardContent>
                  {rfAnalysis.rogueAPs.findings.length === 0 ? (
                    <p className="text-green-400">No rogue APs detected.</p>
                  ) : (
                    <div className="space-y-2">
                      {rfAnalysis.rogueAPs.findings.map((f, i) => (
                        <div key={i} className="text-sm">
                          <span className={f.severity === "high" ? "text-red-400" : "text-yellow-400"}>
                            [{f.severity.toUpperCase()}]
                          </span>{" "}
                          {f.description}
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          ) : (
            <p className="text-muted-foreground">No RF analysis data for this scan.</p>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

- [ ] **Step 5: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/components/persona-card.tsx dashboard/components/compliance-card.tsx dashboard/components/channel-chart.tsx dashboard/app/scans/
git commit -m "add scan detail page with summary, personas, compliance, and RF tabs"
```

---

### Task 8: Trends page

**Files:**
- Create: `dashboard/components/trend-chart.tsx`
- Create: `dashboard/app/trends/page.tsx`

- [ ] **Step 1: Create TrendChart component**

```tsx
// dashboard/components/trend-chart.tsx
"use client";

import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface DataPoint {
  date: string;
  value: number;
}

export function TrendChart({
  data,
  color = "#3b82f6",
  yDomain,
  unit = "",
}: {
  data: DataPoint[];
  color?: string;
  yDomain?: [number, number];
  unit?: string;
}) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data}>
        <XAxis
          dataKey="date"
          tick={{ fontSize: 11, fill: "#a1a1aa" }}
          tickFormatter={(v) => {
            const d = new Date(v);
            return `${d.getDate()}/${d.getMonth() + 1}`;
          }}
        />
        <YAxis
          domain={yDomain ?? ["auto", "auto"]}
          tick={{ fontSize: 11, fill: "#a1a1aa" }}
        />
        <Tooltip
          contentStyle={{ backgroundColor: "#18181b", border: "1px solid #27272a", borderRadius: "8px" }}
          labelStyle={{ color: "#fafafa" }}
          labelFormatter={(v) => new Date(v).toLocaleString()}
          formatter={(value: number) => [`${value}${unit}`, ""]}
        />
        <Line type="monotone" dataKey="value" stroke={color} strokeWidth={2} dot={{ r: 3 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}
```

- [ ] **Step 2: Create the trends page**

```tsx
// dashboard/app/trends/page.tsx
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TrendChart } from "@/components/trend-chart";
import { EmptyState } from "@/components/empty-state";
import { getScans, getScan } from "@/lib/store";

export const dynamic = "force-dynamic";

export default function TrendsPage() {
  const entries = getScans({ limit: 50 });

  if (entries.length < 2) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Trends</h1>
        <EmptyState />
      </div>
    );
  }

  // Load full scans for detailed metrics (newest first, reverse for chronological)
  const chronological = [...entries].reverse();
  const scans = chronological.map((e) => {
    try {
      return getScan(e.scanId);
    } catch {
      return null;
    }
  }).filter(Boolean) as Exclude<ReturnType<typeof getScan>, null>[];

  const securityData = chronological.map((e) => ({
    date: e.timestamp,
    value: e.securityScore,
  }));

  const complianceData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.compliance.overallScore,
  }));

  const hostData = chronological.map((e) => ({
    date: e.timestamp,
    value: e.hostCount,
  }));

  const signalData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.scan.wifi.signal,
  }));

  const snrData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.scan.wifi.snr,
  }));

  const nearbyData = scans.map((s) => ({
    date: s.scan.meta.timestamp,
    value: s.scan.wifi.nearbyNetworks.length,
  }));

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Trends</h1>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardHeader><CardTitle className="text-base">Security Score</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={securityData} color="#22c55e" yDomain={[0, 10]} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Compliance Score</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={complianceData} color="#3b82f6" yDomain={[0, 100]} unit="%" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Host Count</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={hostData} color="#a855f7" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">WiFi Signal</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={signalData} color="#eab308" unit=" dBm" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Signal-to-Noise Ratio</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={snrData} color="#06b6d4" unit=" dB" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Nearby Networks</CardTitle></CardHeader>
          <CardContent>
            <TrendChart data={nearbyData} color="#f97316" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel
git add dashboard/components/trend-chart.tsx dashboard/app/trends/
git commit -m "add trends page with interactive metric charts"
```

---

### Task 9: Update ROADMAP.md

**Files:**
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update Phase 3 status**

Change the Phase 3 section to:

```markdown
## Phase 3: Dashboard (PARTIAL)

- [x] Next.js app with shadcn/ui (dark theme, sidebar nav, Geist fonts)
- [x] Real-time persona perspectives (scan detail personas tab)
- [x] Historical trends and compliance tracking (trends page, compliance tab)
- [ ] PDF/HTML report generation (Phase 3b)
```

- [ ] **Step 2: Commit**

```bash
git add ROADMAP.md
git commit -m "mark Phase 3a dashboard as complete"
```

---

### Task 10: End-to-end integration test

- [ ] **Step 1: Install and build**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npm install
```

- [ ] **Step 2: Start dev server and test all pages**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npx next dev --port 3100 &
sleep 8
echo "=== Overview ==="
curl -s http://localhost:3100 | grep -o "Security Score\|Persona Risk\|Score Trend\|RF Summary" | head -5
echo "=== API /api/scans ==="
curl -s http://localhost:3100/api/scans | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log('Scans:',d.length)"
echo "=== History ==="
curl -s http://localhost:3100/scans | grep -o "Scan History" | head -1
echo "=== Trends ==="
curl -s http://localhost:3100/trends | grep -o "Trends\|Security Score\|Compliance Score" | head -3
echo "=== Scan detail ==="
SCAN_ID=$(curl -s http://localhost:3100/api/scans | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));if(d.length)process.stdout.write(d[0].scanId)")
curl -s "http://localhost:3100/scans/$SCAN_ID" | grep -o "Scan Report\|Summary\|Personas\|Compliance\|RF" | head -5
kill %1 2>/dev/null
```

Expected: all page names and sections found.

- [ ] **Step 3: Test API detail endpoint**

```bash
cd /Users/ismael.martinez/projects/github/wifisentinel/dashboard && npx next dev --port 3100 &
sleep 8
SCAN_ID=$(curl -s http://localhost:3100/api/scans | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));if(d.length)process.stdout.write(d[0].scanId)")
curl -s "http://localhost:3100/api/scans/$SCAN_ID" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log('Has scan:',!!d.scan,'Has compliance:',!!d.compliance,'Has analysis:',!!d.analysis,'Has rf:',!!d.rfAnalysis)"
curl -s "http://localhost:3100/api/scans/$SCAN_ID/rf" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log('Has channelMap:',!!d.channelMap,'Has rogueAPs:',!!d.rogueAPs)"
kill %1 2>/dev/null
```

Expected: all fields present and truthy.
