import { useMemo } from "react";
import { BarList } from "../charts/BarList";
import { LineChart } from "../charts/LineChart";
import { StatTile } from "../charts/StatTile";
import { formatNumber } from "../format";

// Seeded, so the placeholder charts stay the same across renders and reloads.
function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 2 ** 32;
    return s / 2 ** 32;
  };
}

export function makeDummyData() {
  const rand = rng(42);
  const hours = Array.from({ length: 24 }, (_, h) => `${String(h).padStart(2, "0")}:00`);
  const allowed = hours.map((_, h) => Math.round(120 + 80 * Math.sin((h - 6) / 3.8) + rand() * 30));
  const blocked = hours.map(() => Math.round(10 + rand() * 25));
  const rules = [
    { label: "Port scan", value: Math.round(40 + rand() * 60) },
    { label: "Brute force", value: Math.round(20 + rand() * 40) },
    { label: "Malware beacon", value: Math.round(5 + rand() * 20) },
    { label: "Data exfiltration", value: Math.round(rand() * 10) },
  ].sort((a, b) => b.value - a.value);
  return { hours, allowed, blocked, rules };
}

export function DummySection() {
  const { hours, allowed, blocked, rules } = useMemo(makeDummyData, []);
  const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);

  return (
    <>
      <p className="notice">
        <span className="badge badge-warning">
          <span aria-hidden="true">!</span> dummy data
        </span>{" "}
        Not linked to an API route yet: these charts show generated placeholder values.
      </p>
      <div className="tiles">
        <StatTile label="Events (24h)" value={formatNumber(sum(allowed) + sum(blocked))} />
        <StatTile label="Blocked (24h)" value={formatNumber(sum(blocked))} />
        <StatTile label="Rules triggered" value={formatNumber(sum(rules.map((r) => r.value)))} />
      </div>
      <div className="grid">
        <LineChart
          title="Events per hour"
          subtitle="Allowed and blocked traffic over the last 24 hours."
          xLabels={hours}
          series={[
            { name: "Allowed", color: "var(--series-1)", values: allowed },
            { name: "Blocked", color: "var(--series-2)", values: blocked },
          ]}
          format={formatNumber}
        />
        <BarList title="Detections by rule" subtitle="Last 24 hours." rows={rules} format={formatNumber} />
      </div>
    </>
  );
}
