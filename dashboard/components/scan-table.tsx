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
            role="button"
            tabIndex={0}
            className="cursor-pointer"
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
  );
}
