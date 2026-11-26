import type { ComponentType } from "react";
import type { Sample } from "../api";

export interface SectionProps {
  /** Successful polls of `route`, oldest first. Empty for sections without a route. */
  samples: Sample[];
  /** Last polling error for `route`, cleared on the next success. */
  error: string | null;
}

export interface Section {
  id: string;
  title: string;
  /** API route polled for this section; none means it is not wired to the API yet. */
  route?: string;
  Component: ComponentType<SectionProps>;
}
