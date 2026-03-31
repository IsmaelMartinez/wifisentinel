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
