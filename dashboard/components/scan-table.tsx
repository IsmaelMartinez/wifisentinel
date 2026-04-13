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

function MobileCard({ entry }: { entry: IndexEntry }) {
  const router = useRouter();
  return (
    <div
      role="button"
      tabIndex={0}
      className="rounded-lg border border-border bg-card p-3 cursor-pointer active:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      onClick={() => router.push(`/scans/${entry.scanId}`)}
      onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); router.push(`/scans/${entry.scanId}`); } }}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="font-mono text-xs text-muted-foreground">
          {new Date(entry.timestamp).toLocaleString("en-GB", {
            year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit",
          })}
        </span>
        <GradeBadge grade={entry.complianceGrade} className="w-6 h-6 text-xs" />
      </div>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium">{entry.ssid ?? <span className="text-muted-foreground">(hidden)</span>}</p>
          <p className="text-xs text-muted-foreground mt-0.5">
            Score: <span className="font-mono">{entry.securityScore.toFixed(1)}</span> &middot; {entry.hostCount} host{entry.hostCount !== 1 ? "s" : ""}
          </p>
        </div>
        <RiskBadge risk={entry.consensusRisk} />
      </div>
    </div>
  );
}

export function ScanTable({ entries }: { entries: IndexEntry[] }) {
  const router = useRouter();

  return (
    <>
      {/* Mobile: card list */}
      <div className="space-y-2 sm:hidden">
        {entries.map((e) => (
          <MobileCard key={e.scanId} entry={e} />
        ))}
      </div>

      {/* Desktop: table with horizontal scroll */}
      <div className="hidden sm:block overflow-x-auto">
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
                role="button"
                tabIndex={0}
                className="cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                onClick={() => router.push(`/scans/${e.scanId}`)}
                onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); router.push(`/scans/${e.scanId}`); } }}
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
      </div>
    </>
  );
}
