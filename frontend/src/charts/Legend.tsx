export function Legend({ items }: { items: { name: string; color: string }[] }) {
  return (
    <ul className="legend">
      {items.map((it) => (
        <li key={it.name}>
          <span className="swatch" style={{ background: it.color }} />
          {it.name}
        </li>
      ))}
    </ul>
  );
}
