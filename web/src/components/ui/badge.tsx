import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const tones = {
  neutral: "bg-secondary text-secondary-foreground",
  primary: "bg-accent text-accent-foreground",
  good: "bg-good/12 text-[#0a7a0a] dark:text-[#3fd13f] ring-1 ring-inset ring-good/25",
  warning: "bg-warning/15 text-[#8a5a00] dark:text-warning ring-1 ring-inset ring-warning/30",
  serious: "bg-serious/15 text-[#a8471f] dark:text-serious ring-1 ring-inset ring-serious/30",
  critical: "bg-critical/12 text-critical ring-1 ring-inset ring-critical/25",
  outline: "border text-muted-foreground",
};
export type Tone = keyof typeof tones;

export function Badge({ tone = "neutral", className, ...p }: HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return <span className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium", tones[tone], className)} {...p} />;
}
