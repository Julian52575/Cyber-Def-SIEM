import { useLayoutEffect, useRef, useState } from "react";

/**
 * Tracks an element's width, so SVG charts draw at real pixels instead of
 * scaling a fixed viewBox (which shrinks text to unreadable sizes on phones).
 */
export function useWidth<T extends Element>(fallback: number) {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);

  useLayoutEffect(() => {
    const el = ref.current;
    // jsdom (tests) has no ResizeObserver; keep the fallback width there.
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.round(entry.contentRect.width);
      if (w > 0) setWidth(w);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return [ref, width] as const;
}
