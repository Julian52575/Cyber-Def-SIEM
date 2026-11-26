interface Props {
  title: string;
  subtitle?: string;
  rows: { label: string; value: number }[];
  color?: string;
  format?: (n: number) => string;
  empty?: string;
}

/** Horizontal bars, one series: magnitude per category, value at the tip. */
export function BarList({ title, subtitle, rows, color = "var(--series-1)", format = String, empty }: Props) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <figure className="card chart">
      <figcaption>
        <h3>{title}</h3>
        {subtitle && <p className="muted">{subtitle}</p>}
      </figcaption>
      {rows.length === 0 ? (
        <p className="empty">{empty ?? "No data yet."}</p>
      ) : (
        <ul className="bars">
          {rows.map((r) => (
            <li key={r.label} title={`${r.label}: ${format(r.value)}`}>
              <span className="bar-label">{r.label}</span>
              <span className="bar-track">
                <span
                  className="bar"
                  style={{ width: `${(r.value / max) * 100}%`, background: color }}
                />
                <span className="bar-value">{format(r.value)}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </figure>
  );
}
