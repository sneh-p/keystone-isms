import { Tooltip } from "@/components/ui/misc";

export type Segment = { key: string; label: string; value: number; className: string };

/** Single stacked bar with a 2px gap between segments and a labelled legend (identity never colour-only). */
export function StatusBar({ segments, total }: { segments: Segment[]; total?: number }) {
  const sum = total ?? segments.reduce((a, s) => a + s.value, 0);
  return (
    <div>
      <div className="flex h-3 w-full gap-[2px] overflow-hidden rounded-full bg-secondary">
        {segments.filter((s) => s.value > 0).map((s) => (
          <Tooltip key={s.key} content={`${s.label}: ${s.value} (${Math.round((100 * s.value) / (sum || 1))}%)`}>
            <div className={`h-full first:rounded-l-full last:rounded-r-full ${s.className}`} style={{ width: `${(100 * s.value) / (sum || 1)}%` }} />
          </Tooltip>
        ))}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {segments.map((s) => (
          <li key={s.key} className="flex items-center gap-1.5">
            <span className={`size-2.5 rounded-sm ${s.className}`} aria-hidden />
            {s.label} <span className="font-medium tabular-nums text-foreground">{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export const CONTROL_SEGMENTS = (c: Record<string, number>): Segment[] => [
  { key: "implemented", label: "Implemented", value: c.implemented ?? 0, className: "bg-good" },
  { key: "partial", label: "Partial", value: c.partial ?? 0, className: "bg-warning" },
  { key: "planned", label: "Planned", value: c.planned ?? 0, className: "bg-primary/70" },
  { key: "not_started", label: "Not started", value: c.not_started ?? 0, className: "bg-muted-foreground/30" },
  { key: "not_applicable", label: "Not applicable", value: c.not_applicable ?? 0, className: "bg-muted-foreground/10 ring-1 ring-inset ring-border" },
];
