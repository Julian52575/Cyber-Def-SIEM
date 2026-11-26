import { useEffect, useState, type FormEvent } from "react";
import { getJson, type Sample } from "./api";
import { formatClock } from "./format";
import { SECTIONS } from "./sections";

type Health = "not checked" | "checking" | "ok" | "unreachable";

interface RouteData {
  samples: Sample[];
  error: string | null;
}

const URL_KEY = "siem-api-url";
// Where `my_siem --api` listens by default.
export const DEFAULT_API_URL = "http://127.0.0.1:12125";
const TAB_KEY = "siem-tab";
// ~10 minutes of history at the default 5 s interval.
export const MAX_SAMPLES = 120;
const INTERVALS = [2, 5, 10, 30];

// Returns the base URL without a trailing slash, or null if it is not http(s).
export function parseApiUrl(input: string): string | null {
  try {
    const url = new URL(input.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.href.replace(/\/+$/, "");
  } catch {
    return null;
  }
}

// Storage can be unavailable (private mode); the app still works without it.
function load(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function save(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // ignored, see load()
  }
}

const ROUTES = [...new Set(SECTIONS.flatMap((s) => (s.route ? [s.route] : [])))];

export default function App() {
  const [address, setAddress] = useState(() => load(URL_KEY, DEFAULT_API_URL));
  const [health, setHealth] = useState<Health>("not checked");
  const [polling, setPolling] = useState(false);
  const [intervalSec, setIntervalSec] = useState(5);
  const [routes, setRoutes] = useState<Record<string, RouteData>>({});
  const [lastPoll, setLastPoll] = useState<number | null>(null);
  const [tab, setTab] = useState(() => {
    const saved = load(TAB_KEY, "");
    return SECTIONS.some((s) => s.id === saved) ? saved : SECTIONS[0].id;
  });

  const base = parseApiUrl(address);
  const invalid = address.trim() !== "" && base === null;

  function onAddressChange(value: string) {
    setAddress(value);
    save(URL_KEY, value);
    // Results from the previous SIEM would be misleading.
    setHealth("not checked");
    setPolling(false);
    setRoutes({});
    setLastPoll(null);
  }

  function onTab(id: string) {
    setTab(id);
    save(TAB_KEY, id);
  }

  async function checkHealth(e: FormEvent) {
    e.preventDefault();
    if (base === null) return;
    setHealth("checking");
    try {
      const res = await fetch(`${base}/healthz`);
      setHealth(res.ok ? "ok" : "unreachable");
    } catch {
      setHealth("unreachable");
    }
  }

  useEffect(() => {
    if (!polling || base === null) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function pollRoute(route: string) {
      try {
        const data = await getJson(base!, route, controller.signal);
        if (controller.signal.aborted) return;
        setRoutes((prev) => {
          const samples = [...(prev[route]?.samples ?? []), { at: Date.now(), data }];
          return { ...prev, [route]: { samples: samples.slice(-MAX_SAMPLES), error: null } };
        });
      } catch (err) {
        if (controller.signal.aborted) return;
        const message = err instanceof Error ? err.message : String(err);
        setRoutes((prev) => ({
          ...prev,
          [route]: { samples: prev[route]?.samples ?? [], error: message },
        }));
      }
    }

    // Wait for a round to finish before scheduling the next, so a slow API never piles up requests.
    async function tick() {
      await Promise.all(ROUTES.map(pollRoute));
      if (controller.signal.aborted) return;
      setLastPoll(Date.now());
      timer = setTimeout(tick, intervalSec * 1000);
    }
    void tick();

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [polling, base, intervalSec]);

  const active = SECTIONS.find((s) => s.id === tab) ?? SECTIONS[0];
  const activeData = active.route ? routes[active.route] : undefined;

  return (
    <div className="app">
      <header className="topbar">
        <form className="api-bar" onSubmit={checkHealth}>
          <label htmlFor="api-url">SIEM API address</label>
          <div className="api-row">
            <input
              id="api-url"
              type="text"
              inputMode="url"
              placeholder={DEFAULT_API_URL}
              value={address}
              onChange={(e) => onAddressChange(e.target.value)}
              aria-invalid={invalid}
              aria-describedby="api-status"
            />
            <button type="submit" disabled={base === null || health === "checking"}>
              Health check
            </button>
            <button
              type="button"
              className={polling ? "primary active" : "primary"}
              aria-pressed={polling}
              disabled={base === null}
              onClick={() => setPolling((p) => !p)}
            >
              {polling ? "Stop polling" : "Start polling"}
            </button>
            <select
              aria-label="Polling interval"
              value={intervalSec}
              onChange={(e) => setIntervalSec(Number(e.target.value))}
            >
              {INTERVALS.map((s) => (
                <option key={s} value={s}>
                  every {s}s
                </option>
              ))}
            </select>
          </div>
          <p id="api-status" className="muted">
            {invalid ? (
              "Enter an http:// or https:// address."
            ) : (
              <>
                SIEM API: <strong>{health}</strong>
                {" · "}
                {polling ? "polling" : "not polling"}
                {lastPoll !== null && ` · last poll ${formatClock(lastPoll)}`}
              </>
            )}
          </p>
        </form>
      </header>

      <main>
        <h1>Siem</h1>
        <nav className="tabs" role="tablist" aria-label="Sections">
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              type="button"
              role="tab"
              id={`tab-${s.id}`}
              aria-selected={s.id === active.id}
              aria-controls={`panel-${s.id}`}
              onClick={() => onTab(s.id)}
            >
              {s.title}
              <span className="muted tab-route">{s.route ?? "no route"}</span>
            </button>
          ))}
        </nav>
        <section role="tabpanel" id={`panel-${active.id}`} aria-labelledby={`tab-${active.id}`}>
          <active.Component samples={activeData?.samples ?? []} error={activeData?.error ?? null} />
        </section>
      </main>
    </div>
  );
}
