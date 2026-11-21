import * as ProgressP from "@radix-ui/react-progress";
import * as SwitchP from "@radix-ui/react-switch";
import * as Tip from "@radix-ui/react-tooltip";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { Inbox } from "lucide-react";
import { cn } from "@/lib/utils";
import { Sparkline } from "@/components/viz/Sparkline";

/** `label` names what the bar measures for screen readers (WCAG 4.1.2), e.g. "ISO 27001 readiness". */
export function Progress({ value, label, className, tone = "primary" }: { value: number; label: string; className?: string; tone?: "primary" | "good" | "warning" | "critical" }) {
  const color = { primary: "bg-primary", good: "bg-good", warning: "bg-warning", critical: "bg-critical" }[tone];
  return (
    <ProgressP.Root value={value} aria-label={label} className={cn("relative h-2 w-full overflow-hidden rounded-full bg-secondary", className)}>
      <ProgressP.Indicator className={cn("h-full rounded-full transition-all", color)} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </ProgressP.Root>
  );
}

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label?: ReactNode; disabled?: boolean }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-sm">
      <SwitchP.Root checked={checked} onCheckedChange={onChange} disabled={disabled} className="relative h-5 w-9 shrink-0 rounded-full bg-input transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background data-[state=checked]:bg-primary disabled:opacity-50">
        <SwitchP.Thumb className="block size-4 translate-x-0.5 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-[18px]" />
      </SwitchP.Root>
      {label}
    </label>
  );
}

export function Tooltip({ content, children }: { content: ReactNode; children: ReactNode }) {
  return (
    <Tip.Provider delayDuration={200}>
      <Tip.Root>
        <Tip.Trigger asChild>{children}</Tip.Trigger>
        <Tip.Portal>
          <Tip.Content sideOffset={4} className="z-50 max-w-xs rounded-md bg-foreground px-2.5 py-1.5 text-xs leading-relaxed text-background shadow-pop animate-fade-in">
            {content}
          </Tip.Content>
        </Tip.Portal>
      </Tip.Root>
    </Tip.Provider>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-muted", className)} />;
}

export function Empty({ icon: Icon = Inbox, title, children, action }: { icon?: any; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed bg-card/60 px-6 py-14 text-center">
      <div className="mb-4 grid size-12 place-items-center rounded-xl border bg-card text-muted-foreground shadow-card">
        <Icon className="size-5" aria-hidden />
      </div>
      <p className="font-semibold tracking-tight">{title}</p>
      {children && <p className="mt-1 max-w-md text-sm text-muted-foreground">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function PageHeader({ title, description, actions, icon: Icon }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; icon?: any }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
      {/* The title block may shrink to 24rem, so actions stay on the right on wide screens and wrap below on narrow ones. */}
      <div className="flex min-w-0 flex-1 basis-96 items-start gap-3.5">
        {Icon && (
          <div className="hidden size-10 shrink-0 place-items-center rounded-lg border bg-card text-primary shadow-card sm:grid">
            <Icon className="size-5" aria-hidden />
          </div>
        )}
        <div className="min-w-0">
          <h1 className="text-[1.625rem] font-semibold leading-10 tracking-[-0.02em]">{title}</h1>
          {description && <p className="mt-0.5 max-w-3xl text-sm leading-relaxed text-muted-foreground">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export type StatTrend = { values: (number | null)[]; days: string[]; upIsGood?: boolean | null; format?: (v: number) => string };

/** Stat tile: label, value, optional change since last week and 12-week sparkline; the whole tile links when `to` is set. */
export function Stat({ label, value, hint, icon: Icon, tone, to, trend }: { label: ReactNode; value: ReactNode; hint?: ReactNode; icon?: any; tone?: "good" | "warning" | "critical"; to?: string; trend?: StatTrend }) {
  const toneCls = tone === "critical" ? "text-critical-fg" : tone === "warning" ? "text-warning-fg" : tone === "good" ? "text-good-fg" : "";
  const bar = tone === "critical" ? "bg-critical" : tone === "warning" ? "bg-warning" : tone === "good" ? "bg-good" : null;
  const vals = trend?.values ?? [];
  const now = vals[vals.length - 1], prev = vals[vals.length - 2];
  const change = typeof now === "number" && typeof prev === "number" ? Math.round((now - prev) * 10) / 10 : null;
  const fmt = trend?.format ?? String;
  const better = change && trend?.upIsGood != null ? (change > 0) === trend.upIsGood : null;
  const body = (
    <>
      {/* A status tile carries its tone as a short bar as well as the number's colour. */}
      {bar && <span className={cn("absolute inset-x-0 top-0 h-0.5", bar)} aria-hidden />}
      <div className="flex items-start justify-between gap-2 text-[0.8125rem] font-medium leading-5 text-muted-foreground">
        <span>{label}</span>
        {Icon && <Icon className="mt-0.5 size-4 shrink-0 opacity-80" aria-hidden />}
      </div>
      <div className="mt-1.5 flex flex-wrap items-baseline gap-x-2">
        <span className={cn("text-[1.75rem] font-semibold leading-9 tracking-[-0.02em] tabular-nums", toneCls)}>{value}</span>
        {change !== null && (
          <span className={cn("text-xs font-medium", better === true ? "text-good-fg" : better === false ? "text-critical-fg" : "text-muted-foreground")}>
            {change === 0 ? "no change" : `${change > 0 ? "▲ +" : "▼ −"}${fmt(Math.abs(change))}`} <span className="font-normal text-muted-foreground">vs last week</span>
          </span>
        )}
      </div>
      {hint && <div className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{hint}</div>}
      {trend && <div className="mt-auto pt-1"><Sparkline values={trend.values} days={trend.days} label={typeof label === "string" ? label : "Trend"} format={fmt} /></div>}
    </>
  );
  // h-full + flex column: tiles in a row share one height and their sparklines line up along the bottom.
  const cls = "relative flex h-full flex-col overflow-hidden rounded-lg border bg-card p-4 shadow-card";
  return to ? <Link to={to} className={cn(cls, "transition-[border-color,box-shadow] hover:border-primary/40 hover:shadow-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring")}>{body}</Link> : <div className={cls}>{body}</div>;
}

export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-2 text-sm">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A titled block. `level` keeps the heading outline intact (WCAG 1.3.1): 2 directly under a page title, 3 in a dialog. */
export function Section({ title, children, action, level = 4 }: { title: ReactNode; children: ReactNode; action?: ReactNode; level?: 2 | 3 | 4 }) {
  const H = `h${level}` as "h2" | "h3" | "h4";
  return (
    <section className="mb-6">
      <div className="mb-2.5 flex items-center justify-between gap-3">
        <H className="text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">{title}</H>
        {action}
      </div>
      {children}
    </section>
  );
}
