import { useState, type MouseEvent } from "react";
import { Legend } from "./Legend";
import { useWidth } from "./useWidth";

export interface LineSeries {
  name: string;
  color: string;
  values: (number | null)[];
}

interface Props {
  title: string;
  subtitle?: string;
  series: LineSeries[];
  xLabels: string[];
  format?: (n: number) => string;
  empty?: string;
}

const H = 220;
const M = { l: 44, r: 16, t: 12, b: 28 };
const PH = H - M.t - M.b;

// Clean tick steps (1, 2, 5 x 10^k) so the axis reads at a glance.
export function niceTicks(max: number, count = 4): number[] {
  const top = Math.max(max, 1);
  const raw = top / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((f) => f * mag).find((s) => s >= raw) ?? raw;
  const ticks = [];
  for (let v = 0; v < top + step; v += step) ticks.push(Math.round(v * 1e6) / 1e6);
  return ticks;
}

export function LineChart({ title, subtitle, series, xLabels, format = String, empty }: Props) {
  const [hover, setHover] = useState<number | null>(null);
  const [plotRef, W] = useWidth<HTMLDivElement>(640);
  const PW = W - M.l - M.r;
  const n = xLabels.length;
  const all = series.flatMap((s) => s.values.filter((v): v is number => v !== null));
  const ticks = niceTicks(all.length ? Math.max(...all) : 0);
  const yMax = ticks[ticks.length - 1];

  const x = (i: number) => M.l + (n <= 1 ? PW / 2 : (i * PW) / (n - 1));
  const y = (v: number) => M.t + PH - (v / yMax) * PH;

  function path(values: (number | null)[]) {
    let d = "";
    let pen = false;
    values.forEach((v, i) => {
      if (v === null) {
        pen = false;
        return;
      }
      d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
      pen = true;
    });
    return d;
  }

  function onMove(e: MouseEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    if (rect.width === 0 || n === 0) return;
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const i = n <= 1 ? 0 : Math.round(((px - M.l) / PW) * (n - 1));
    setHover(Math.min(n - 1, Math.max(0, i)));
  }

  const xTickIdx = n <= 1 ? [0] : W < 420 ? [0, n - 1] : [...new Set([0, Math.floor((n - 1) / 2), n - 1])];

  return (
    <figure className="card chart">
      <figcaption>
        <h3>{title}</h3>
        {subtitle && <p className="muted">{subtitle}</p>}
      </figcaption>
      {series.length >= 2 && <Legend items={series} />}
      {n === 0 ? (
        <p className="empty">{empty ?? "No data yet."}</p>
      ) : (
        <div className="plot" ref={plotRef}>
          <svg
            width={W}
            height={H}
            viewBox={`0 0 ${W} ${H}`}
            role="img"
            aria-label={title}
            onMouseMove={onMove}
            onMouseLeave={() => setHover(null)}
          >
            {ticks.map((t) => (
              <g key={t}>
                <line className={t === 0 ? "axis" : "grid"} x1={M.l} x2={W - M.r} y1={y(t)} y2={y(t)} />
                <text className="tick" x={M.l - 8} y={y(t)} textAnchor="end" dominantBaseline="middle">
                  {format(t)}
                </text>
              </g>
            ))}
            {xTickIdx.map((i) => (
              <text
                key={i}
                className="tick"
                x={x(i)}
                y={H - 8}
                textAnchor={n <= 1 ? "middle" : i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
              >
                {xLabels[i]}
              </text>
            ))}
            {series.map((s) => (
              <path key={s.name} d={path(s.values)} fill="none" stroke={s.color} className="line" />
            ))}
            {series.map((s) => {
              const last = s.values.length - 1;
              const v = s.values[last];
              return v === null || v === undefined || hover !== null ? null : (
                <circle key={s.name} cx={x(last)} cy={y(v)} r={4} fill={s.color} className="dot" />
              );
            })}
            {hover !== null && (
              <g>
                <line className="crosshair" x1={x(hover)} x2={x(hover)} y1={M.t} y2={M.t + PH} />
                {series.map((s) => {
                  const v = s.values[hover];
                  return v === null || v === undefined ? null : (
                    <circle key={s.name} cx={x(hover)} cy={y(v)} r={4} fill={s.color} className="dot" />
                  );
                })}
              </g>
            )}
          </svg>
          {hover !== null && (
            <div
              className="tooltip"
              role="status"
              style={{
                left: `${(x(hover) / W) * 100}%`,
                transform: `translateX(${hover > n / 2 ? "calc(-100% - 12px)" : "12px"})`,
              }}
            >
              <div className="tooltip-title">{xLabels[hover]}</div>
              {series.map((s) => (
                <div key={s.name} className="tooltip-row">
                  <span className="swatch" style={{ background: s.color }} />
                  <span>{s.name}</span>
                  <strong>{s.values[hover] === null ? "–" : format(s.values[hover] ?? 0)}</strong>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {n > 0 && (
        <details>
          <summary>Show table</summary>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                {series.map((s) => (
                  <th key={s.name}>{s.name}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {xLabels.map((label, i) => (
                <tr key={i}>
                  <td>{label}</td>
                  {series.map((s) => (
                    <td key={s.name}>{s.values[i] === null ? "–" : format(s.values[i] ?? 0)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </figure>
  );
}
