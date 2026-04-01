// dashboard/app/scans/page.tsx
import { Card, CardContent } from "@/components/ui/card";
import { ScanTable } from "@/components/scan-table";
import { EmptyState } from "@/components/empty-state";
import { ScanRunner } from "@/components/scan-runner";
import { getScans } from "@/lib/store";

export const revalidate = 60;

export default function HistoryPage() {
  const entries = getScans({ limit: 100 });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Scan History</h1>
      <ScanRunner />
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
