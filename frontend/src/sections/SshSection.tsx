import type { SshSnapshot } from "../api";
import { BarList } from "../charts/BarList";
import { FlowDiagram } from "../charts/FlowDiagram";
import { LineChart } from "../charts/LineChart";
import { StatTile, StatusBadge } from "../charts/StatTile";
import { formatBytes, formatClock, formatDuration, formatNumber } from "../format";
import type { SectionProps } from "./types";

const AUTH_KINDS = [
  { kind: "login_success", label: "Successful login" },
  { kind: "login_failure", label: "Failed login" },
  { kind: "invalid_user", label: "Invalid user" },
  { kind: "logout", label: "Logout" },
];

const failedLogins = (s: SshSnapshot) => (s.counts.login_failure ?? 0) + (s.counts.invalid_user ?? 0);

/**
 * Counts are running totals since the SIEM started; the per-poll increase is
 * what shows activity. A drop means the SIEM restarted, so that point is unknown.
 */
export function perPoll(totals: number[]): (number | null)[] {
  return totals.map((v, i) => (i === 0 || v < totals[i - 1] ? null : v - totals[i - 1]));
}

export function topFailedIps(s: SshSnapshot, limit = 8) {
  const byIp = new Map<string, number>();
  for (const l of s.recent_logins) {
    if (l.kind === "login_failure" || l.kind === "invalid_user") byIp.set(l.ip, (byIp.get(l.ip) ?? 0) + 1);
  }
  return [...byIp.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
}

export function SshSection({ samples, error }: SectionProps) {
  const history = samples as { at: number; data: SshSnapshot }[];
  const latest = history.at(-1)?.data;

  if (!latest) {
    return (
      <>
        {error && <p className="error">Cannot read /ssh: {error}</p>}
        <p className="empty card">
          No data yet. Start polling, with my_siem running as <code>my_siem --api ssh</code>.
        </p>
      </>
    );
  }

  const times = history.map((s) => formatClock(s.at));
  const totalBytes = latest.active_connections.reduce((sum, c) => sum + c.bytes, 0);

  return (
    <>
      {error && <p className="error">Last poll failed: {error}. Showing the previous data.</p>}

      <div className="sources">
        {Object.entries(latest.sources).map(([name, src]) => (
          <div key={name} className="source">
            <strong>{name === "sshd_log" ? "sshd logs" : name === "network" ? "Network sniffer" : name}</strong>
            <StatusBadge status={src.status} />
            <span className="muted">{src.detail}</span>
          </div>
        ))}
        {Object.keys(latest.sources).length === 0 && <span className="muted">No source started yet.</span>}
      </div>

      <div className="tiles">
        <StatTile label="Uptime" value={formatDuration(latest.uptime)} sub={`since ${formatClock(latest.started_at)}`} />
        <StatTile
          label="Active connections"
          value={formatNumber(latest.active_connections.length)}
          sub={formatBytes(totalBytes)}
        />
        <StatTile label="Successful logins" value={formatNumber(latest.counts.login_success ?? 0)} />
        <StatTile label="Failed logins" value={formatNumber(failedLogins(latest))} sub="incl. invalid users" />
        <StatTile label="Alerts" value={formatNumber(latest.counts.alerts ?? 0)} />
      </div>

      <div className="grid">
        <LineChart
          title="Active connections"
          subtitle="Open SSH connections at each poll."
          xLabels={times}
          series={[
            {
              name: "Active connections",
              color: "var(--series-1)",
              values: history.map((s) => s.data.active_connections.length),
            },
          ]}
          format={formatNumber}
        />
        <LineChart
          title="New events per poll"
          subtitle="Increase since the previous poll."
          xLabels={times}
          series={[
            {
              name: "New connections",
              color: "var(--series-1)",
              values: perPoll(history.map((s) => s.data.counts.conn_opened ?? 0)),
            },
            {
              name: "Failed logins",
              color: "var(--series-2)",
              values: perPoll(history.map((s) => failedLogins(s.data))),
            },
            {
              name: "Alerts",
              color: "var(--series-3)",
              values: perPoll(history.map((s) => s.data.counts.alerts ?? 0)),
            },
          ]}
          format={formatNumber}
        />
        <BarList
          title="Authentication outcomes"
          subtitle="Since the SIEM started."
          rows={AUTH_KINDS.map((k) => ({ label: k.label, value: latest.counts[k.kind] ?? 0 }))}
          format={formatNumber}
        />
        <BarList
          title="Top failing source addresses"
          subtitle={`Failed logins among the last ${latest.recent_logins.length} logins.`}
          rows={topFailedIps(latest)}
          format={formatNumber}
          empty="No failed login."
        />
      </div>

      <FlowDiagram connections={latest.active_connections} />

      <div className="card">
        <h3>Recent alerts</h3>
        {latest.recent_alerts.length === 0 ? (
          <p className="empty">No alert.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Alert</th>
                <th>Address</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {[...latest.recent_alerts].reverse().map((a, i) => (
                <tr key={i}>
                  <td>{formatClock(a.at)}</td>
                  <td>
                    <span className="badge badge-critical">
                      <span aria-hidden="true">✕</span> {a.name}
                    </span>
                  </td>
                  <td>{a.ip}</td>
                  <td>{a.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h3>Recent logins</h3>
        {latest.recent_logins.length === 0 ? (
          <p className="empty">No login seen.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Outcome</th>
                <th>User</th>
                <th>From</th>
                <th>Method</th>
              </tr>
            </thead>
            <tbody>
              {[...latest.recent_logins].reverse().map((l, i) => (
                <tr key={i}>
                  <td>{formatClock(l.at)}</td>
                  <td>{AUTH_KINDS.find((k) => k.kind === l.kind)?.label ?? l.kind}</td>
                  <td>{l.user}</td>
                  <td>
                    {l.ip}:{l.port}
                  </td>
                  <td>{l.method ?? "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <details className="card">
        <summary>Monitor configuration</summary>
        <dl className="config">
          {Object.entries(latest.config).map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{JSON.stringify(v)}</dd>
            </div>
          ))}
        </dl>
      </details>
    </>
  );
}
