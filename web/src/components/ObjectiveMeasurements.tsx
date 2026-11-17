import { useState } from "react";
import { LineChart } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { DataTable } from "@/components/ui/table";
import { DateInput } from "@/components/forms";

/**
 * Trend of an objective's measurements (ISO 27001 9.1). One series, so no legend: the dialog title names it. A 2px line
 * in the accent, markers on each measurement, a dashed target line when the target is a number, and a hover tooltip.
 * Colours are the app's validated accent and grey (see Sparkline).
 */
function Trend({ points, target }: { points: { day: string; value: number }[]; target: number | null }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length < 2) return <p className="text-sm text-muted-foreground">Two or more measurements draw a trend.</p>;
  const W = 560, H = 180, padX = 40, padY = 16;
  const values = points.map((p) => p.value).concat(target !== null ? [target] : []);
  const min = Math.min(...values), max = Math.max(...values);
  const x = (i: number) => padX + (i * (W - padX - 12)) / (points.length - 1);
  const y = (v: number) => (max === min ? H / 2 : H - padY - ((v - min) * (H - 2 * padY)) / (max - min));
  const d = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join("");
  const label = `Measurements: ${points.map((p) => `${fmtDate(p.day)} ${p.value}`).join(", ")}${target !== null ? `; target ${target}` : ""}`;
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full overflow-visible" role="img" aria-label={label}
        onPointerLeave={() => setHover(null)}
        onPointerMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const i = Math.round((((e.clientX - r.left) / r.width) * W - padX) / ((W - padX - 12) / (points.length - 1)));
          setHover(Math.max(0, Math.min(points.length - 1, i)));
        }}>
        {[min, max].map((v) => <text key={v} x={padX - 6} y={y(v) + 4} textAnchor="end" className="fill-muted-foreground text-[10px]">{v}</text>)}
        <line x1={padX} x2={W - 12} y1={H - padY} y2={H - padY} className="stroke-border" strokeWidth={1} />
        {target !== null && <>
          <line x1={padX} x2={W - 12} y1={y(target)} y2={y(target)} strokeDasharray="4 4" strokeWidth={1.5} className="stroke-[#575760] dark:stroke-[#71717a]" />
          <text x={W - 12} y={y(target) - 4} textAnchor="end" className="fill-muted-foreground text-[10px]">Target {target}</text>
        </>}
        <path d={d} fill="none" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="stroke-primary" />
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={padY} y2={H - padY} className="stroke-border" strokeWidth={1} />}
        {points.map((p, i) => <circle key={i} cx={x(i)} cy={y(p.value)} r={i === hover ? 5 : 3.5} className="fill-primary stroke-card" strokeWidth={2} />)}
      </svg>
      {hover !== null && (
        <div role="tooltip" className="pointer-events-none absolute top-0 z-10 -translate-x-1/2 whitespace-nowrap rounded-md border bg-popover px-2 py-1 text-xs shadow-md" style={{ left: `${(x(hover) / W) * 100}%` }}>
          <span className="text-muted-foreground">{fmtDate(points[hover].day)}</span> <span className="font-semibold">{points[hover].value}</span>
        </div>
      )}
    </div>
  );
}

export function ObjectiveMeasurements({ objective, onClose }: { objective: any; onClose: () => void }) {
  const { can } = useAuth();
  const { data } = useApi<any>(`/org/objectives/${objective.id}/measurements`);
  const [f, setF] = useState<{ value: string; measured_on: string | null; note: string }>({ value: "", measured_on: null, note: "" });
  const add = useAction(() => api(`/org/objectives/${objective.id}/measurements`, { body: { value: Number(f.value), measured_on: f.measured_on, note: f.note || null } }),
    { success: "Measurement recorded.", invalidate: ["/org"], onSuccess: () => setF({ value: "", measured_on: null, note: "" }) });
  const target = objective.target !== null && objective.target !== "" && !Number.isNaN(Number(objective.target)) ? Number(objective.target) : null;
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} extraWide title={objective.title}
      description={objective.metric_key && data ? `Recorded every day from “${data.metrics[objective.metric_key]}”.` : objective.measure ?? undefined}>
      {!data ? <Skeleton className="h-48" /> : (
        <div className="space-y-5">
          <Trend points={data.measurements.map((m: any) => ({ day: m.measured_on, value: m.value }))} target={target} />
          {can("org.write") && (
            <div className="flex flex-wrap items-end gap-2 rounded-lg border p-3">
              <Field label="Value" className="w-28"><Input type="number" value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} /></Field>
              <Field label="Measured on" className="w-44"><DateInput ariaLabel="Measured on" value={f.measured_on} onChange={(v) => setF({ ...f, measured_on: v })} /></Field>
              <Field label="Note" className="min-w-40 flex-1"><Input value={f.note} onChange={(e) => setF({ ...f, note: e.target.value })} /></Field>
              <Button disabled={f.value === "" || Number.isNaN(Number(f.value))} loading={add.isPending} onClick={() => add.mutate(undefined)}><LineChart /> Record</Button>
            </div>
          )}
          <DataTable rows={[...data.measurements].reverse()} rowKey={(m: any) => m.id} empty="No measurements yet." columns={[
            { key: "d", header: "Date", cell: (m: any) => fmtDate(m.measured_on) },
            { key: "v", header: "Value", cell: (m: any) => <span className="tabular-nums">{m.value}</span> },
            { key: "s", header: "Source", cell: (m: any) => (m.source === "metric" ? "Daily metric" : m.recorded_by) },
            { key: "n", header: "Note", cell: (m: any) => m.note ?? "" },
          ]} />
        </div>
      )}
    </Dialog>
  );
}
