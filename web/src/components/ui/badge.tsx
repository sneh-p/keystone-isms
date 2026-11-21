import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const tones = {
  neutral: "bg-secondary text-secondary-foreground ring-1 ring-inset ring-foreground/5",
  primary: "bg-accent text-accent-foreground ring-1 ring-inset ring-primary/15",
  good: "bg-good/10 text-good-fg ring-1 ring-inset ring-good/25",
  warning: "bg-warning/15 text-warning-fg ring-1 ring-inset ring-warning/35",
  serious: "bg-serious/15 text-serious-fg ring-1 ring-inset ring-serious/30",
  critical: "bg-critical/10 text-critical-fg ring-1 ring-inset ring-critical/25",
  outline: "text-muted-foreground ring-1 ring-inset ring-border",
};
export type Tone = keyof typeof tones;

export function Badge({ tone = "neutral", className, ...p }: HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return <span className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium leading-4", tones[tone], className)} {...p} />;
}
