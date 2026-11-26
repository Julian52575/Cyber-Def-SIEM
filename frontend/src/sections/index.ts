import { DummySection } from "./DummySection";
import { SshSection } from "./SshSection";
import type { Section } from "./types";

// Add a section here; polling picks up its route automatically.
export const SECTIONS: Section[] = [
  { id: "ssh", title: "SSH", route: "/ssh", Component: SshSection },
  { id: "dummy", title: "Dummy", Component: DummySection },
];
