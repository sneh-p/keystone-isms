import { cn } from "@/lib/utils";

/**
 * Keystone's mark: an arch whose centre stone is lit, drawn in JSX (no SVG built from strings, SC-XSS-003).
 * `tone="light"` is for dark brand surfaces; the default sits on the primary colour.
 */
export function BrandMark({ className, tone = "primary" }: { className?: string; tone?: "primary" | "light" }) {
  return (
    <svg viewBox="0 0 32 32" className={cn("size-8 shrink-0", className)} aria-hidden focusable="false">
      <rect width="32" height="32" rx="8" className={tone === "light" ? "fill-white/15" : "fill-primary"} />
      <path d="M8 25v-8a8 8 0 0 1 16 0v8" fill="none" strokeWidth="3" strokeLinecap="round" className={tone === "light" ? "stroke-white/45" : "stroke-primary-foreground/45"} />
      <path d="M12.6 6.5h6.8l-1.5 7.2h-3.8z" className={tone === "light" ? "fill-white" : "fill-primary-foreground"} />
    </svg>
  );
}
