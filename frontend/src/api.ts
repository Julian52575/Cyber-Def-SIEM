// Shapes served by the my_siem API (src/my_siem/api.py, ssh/state.py).

export interface SourceStatus {
  status: string;
  detail: string;
}

export interface ActiveConnection {
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  started: string;
  packets: number;
  bytes: number;
  duration: number;
}

export interface Login {
  at: string;
  kind: "login_success" | "login_failure" | "invalid_user" | "logout";
  user: string;
  ip: string;
  port: number;
  pid: number;
  method: string | null;
}

export interface Alert {
  at: string;
  name: string;
  ip: string;
  message: string;
}

export interface SshSnapshot {
  started_at: string;
  uptime: number;
  config: Record<string, unknown>;
  sources: Record<string, SourceStatus>;
  counts: Record<string, number>;
  active_connections: ActiveConnection[];
  recent_logins: Login[];
  recent_alerts: Alert[];
}

/** One successful poll of a route. */
export interface Sample<T = unknown> {
  at: number;
  data: T;
}

export async function getJson(base: string, route: string, signal?: AbortSignal): Promise<unknown> {
  const res = await fetch(`${base}${route}`, { signal });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
