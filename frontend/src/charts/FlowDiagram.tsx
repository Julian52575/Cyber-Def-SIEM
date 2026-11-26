import { formatBytes, formatDuration } from "../format";
import type { ActiveConnection } from "../api";
import { useWidth } from "./useWidth";

const ROW = 34;
const MAX_CLIENTS = 10;

interface Edge {
  client: string;
  server: string;
  conns: ActiveConnection[];
}

/** Who is connected to which SSH endpoint right now: clients left, servers right. */
export function FlowDiagram({ connections }: { connections: ActiveConnection[] }) {
  const [ref, W] = useWidth<HTMLDivElement>(640);
  // Room for an IPv4 address and port at 13px; narrower on phones.
  const NODE_W = Math.min(190, Math.floor(W * 0.4));
  const byClient = new Map<string, ActiveConnection[]>();
  for (const c of connections) byClient.set(c.client_ip, [...(byClient.get(c.client_ip) ?? []), c]);

  const ranked = [...byClient.entries()].sort((a, b) => b[1].length - a[1].length);
  const shown = ranked.slice(0, MAX_CLIENTS);
  const hidden = ranked.slice(MAX_CLIENTS);
  const clients = shown.map(([ip]) => ip);
  if (hidden.length) clients.push(`+${hidden.length} more`);

  const edgeMap = new Map<string, Edge>();
  for (const [ip, conns] of ranked) {
    const client = clients.includes(ip) ? ip : clients[clients.length - 1];
    for (const c of conns) {
      const server = `${c.server_ip}:${c.server_port}`;
      const key = `${client}|${server}`;
      const e = edgeMap.get(key) ?? { client, server, conns: [] };
      e.conns.push(c);
      edgeMap.set(key, e);
    }
  }
  const servers = [...new Set([...edgeMap.values()].map((e) => e.server))].sort();
  const edges = [...edgeMap.values()];

  const rows = Math.max(clients.length, servers.length, 1);
  const H = rows * ROW + 16;
  const cy = (i: number, count: number) => 8 + ((rows - count) * ROW) / 2 + i * ROW + ROW / 2;
  const leftX = NODE_W;
  const rightX = W - NODE_W;

  return (
    <figure className="card chart">
      <figcaption>
        <h3>Active SSH connections</h3>
        <p className="muted">Client addresses (left) connected to this host's SSH endpoints (right).</p>
      </figcaption>
      <div ref={ref}>
      {connections.length === 0 ? (
        <p className="empty">No active connection.</p>
      ) : (
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Active SSH connections diagram" className="flow">
          {edges.map((e) => {
            const y1 = cy(clients.indexOf(e.client), clients.length);
            const y2 = cy(servers.indexOf(e.server), servers.length);
            const mid = (leftX + rightX) / 2;
            const bytes = e.conns.reduce((s, c) => s + c.bytes, 0);
            const longest = Math.max(...e.conns.map((c) => c.duration));
            return (
              <g key={`${e.client}|${e.server}`} className="edge">
                <title>
                  {`${e.client} → ${e.server}: ${e.conns.length} connection(s), ${formatBytes(bytes)}, longest ${formatDuration(longest)}`}
                </title>
                <path d={`M${leftX},${y1} C${mid},${y1} ${mid},${y2} ${rightX},${y2}`} />
                {e.conns.length > 1 && (
                  <text x={mid} y={(y1 + y2) / 2 - 6} textAnchor="middle" className="tick">
                    ×{e.conns.length}
                  </text>
                )}
              </g>
            );
          })}
          {clients.map((ip, i) => (
            <g key={ip} className="node">
              <rect x={4} y={cy(i, clients.length) - 12} width={NODE_W - 8} height={24} rx={6} />
              <text x={14} y={cy(i, clients.length)} dominantBaseline="middle">
                {ip}
              </text>
            </g>
          ))}
          {servers.map((s, i) => (
            <g key={s} className="node node-server">
              <rect x={rightX + 4} y={cy(i, servers.length) - 12} width={NODE_W - 8} height={24} rx={6} />
              <text x={rightX + 14} y={cy(i, servers.length)} dominantBaseline="middle">
                {s}
              </text>
            </g>
          ))}
        </svg>
      )}
      </div>
    </figure>
  );
}
