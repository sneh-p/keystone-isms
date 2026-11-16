import { useState } from "react";
import { fmtDate } from "@/lib/utils";

/**
 * Weekly trend for a stat tile: a 2px line in the de-emphasis grey with the current point in the accent.
 * Colours validated with the dataviz skill's validator (light #575760 / #5048e5 on #ffffff, dark #71717a / #908bf9
 * on #18181b: separation and contrast pass). Hover shows the week and value; the accessible name lists every point.
 */
export function Sparkline({ values, days, label, format = String }: { values: (number | null)[]; days: string[]; label: string; format?: (v: number) => string }) {
  const [hover, setHover] = useState<number | null>(null);
  const pts = values.map((v, i) => ({ v, i })).filter((p): p is { v: number; i: number } => typeof p.v === "number");
  if (pts.length < 2) return null;
  const W = 200, H = 36, pad = 6;
  const min = Math.min(...pts.map((p) => p.v)), max = Math.max(...pts.map((p) => p.v));
  const x = (i: number) => pad + (i * (W - 2 * pad)) / (values.length - 1);
  const y = (v: number) => (max === min ? H / 2 : H - pad - ((v - min) * (H - 2 * pad)) / (max - min));
  const d = pts.map((p, k) => `${k ? "L" : "M"}${x(p.i).toFixed(1)},${y(p.v).toFixed(1)}`).join("");
  const last = pts[pts.length - 1];
  const when = (i: number) => (i === values.length - 1 ? "Today" : `Week ending ${fmtDate(days[i])}`);
  const summary = `${label}, last ${values.length} weeks: ${pts.map((p) => format(p.v)).join(", ")}`;
  const h = hover !== null && typeof values[hover] === "number" ? hover : null;
  return (
    <div className="relative mt-2">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full overflow-visible" role="img" aria-label={summary}
        onPointerLeave={() => setHover(null)}
        onPointerMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const i = Math.round(((e.clientX - r.left) / r.width * W - pad) / ((W - 2 * pad) / (values.length - 1)));
          setHover(Math.max(0, Math.min(values.length - 1, i)));
        }}>
        <path d={d} fill="none" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="stroke-[#575760] dark:stroke-[#71717a]" />
        {h !== null && h !== last.i && <circle cx={x(h)} cy={y(values[h] as number)} r={3} className="fill-[#575760] stroke-card dark:fill-[#71717a]" strokeWidth={2} />}
        <circle cx={x(last.i)} cy={y(last.v)} r={4} className="fill-primary stroke-card" strokeWidth={2} />
      </svg>
      {h !== null && (
        <div role="tooltip" className="pointer-events-none absolute top-full z-10 mt-1 -translate-x-1/2 whitespace-nowrap rounded-md border bg-popover px-2 py-1 text-xs shadow-md"
          style={{ left: `${(x(h) / W) * 100}%` }}>
          <span className="text-muted-foreground">{when(h)}</span> <span className="font-semibold">{format(values[h] as number)}</span>
        </div>
      )}
    </div>
  );
}
