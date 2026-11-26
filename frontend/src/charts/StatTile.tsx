import type { ReactNode } from "react";

export function StatTile({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="card tile">
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="muted tile-sub">{sub}</div>}
    </div>
  );
}

const ICONS: Record<string, string> = { running: "✓", failed: "✕" };

/** Status never rides on color alone: icon + label + color. */
export function StatusBadge({ status }: { status: string }) {
  const tone = status === "running" ? "good" : status === "failed" ? "critical" : "warning";
  return (
    <span className={`badge badge-${tone}`}>
      <span aria-hidden="true">{ICONS[status] ?? "•"}</span> {status}
    </span>
  );
}
