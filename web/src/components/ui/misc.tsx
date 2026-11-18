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
      <SwitchP.Root checked={checked} onCheckedChange={onChange} disabled={disabled} className="relative h-5 w-9 rounded-full bg-input transition-colors data-[state=checked]:bg-primary disabled:opacity-50">
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
          <Tip.Content sideOffset={4} className="z-50 max-w-xs rounded-md bg-foreground px-2.5 py-1.5 text-xs text-background shadow-md animate-fade-in">
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
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed px-6 py-14 text-center">
      <div className="mb-3 rounded-full bg-muted p-3">
        <Icon className="size-6 text-muted-foreground" />
      </div>
      <p className="font-medium">{title}</p>
      {children && <p className="mt-1 max-w-md text-sm text-muted-foreground">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function PageHeader({ title, description, actions, icon: Icon }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; icon?: any }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      {/* The title block may shrink to 24rem, so actions stay on the right on wide screens and wrap below on narrow ones. */}
      <div className="flex min-w-0 flex-1 basis-96 items-start gap-3">
        {Icon && (
          <div className="mt-0.5 rounded-lg bg-accent p-2 text-accent-foreground">
            <Icon className="size-5" />
          </div>
        )}
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export type StatTrend = { values: (number | null)[]; days: string[]; upIsGood?: boolean | null; format?: (v: number) => string };

/** Stat tile: label, value, optional change since last week and 12-week sparkline; the whole tile links when `to` is set. */
export function Stat({ label, value, hint, icon: Icon, tone, to, trend }: { label: ReactNode; value: ReactNode; hint?: ReactNode; icon?: any; tone?: "good" | "warning" | "critical"; to?: string; trend?: StatTrend }) {
  const toneCls = tone === "critical" ? "text-critical" : tone === "warning" ? "text-[#b07400] dark:text-warning" : tone === "good" ? "text-[#0a7a0a] dark:text-good" : "";
  const vals = trend?.values ?? [];
  const now = vals[vals.length - 1], prev = vals[vals.length - 2];
  const change = typeof now === "number" && typeof prev === "number" ? Math.round((now - prev) * 10) / 10 : null;
  const fmt = trend?.format ?? String;
  const better = change && trend?.upIsGood != null ? (change > 0) === trend.upIsGood : null;
  const body = (
    <>
      <div className="flex items-center justify-between gap-2 text-sm text-muted-foreground">
        <span>{label}</span>
        {Icon && <Icon className="size-4 shrink-0" aria-hidden />}
      </div>
      <div className="mt-2 flex flex-wrap items-baseline gap-x-2">
        <span className={cn("text-2xl font-semibold tracking-tight", toneCls)}>{value}</span>
        {change !== null && (
          <span className={cn("text-xs font-medium", better === true ? "text-[#0a7a0a] dark:text-good" : better === false ? "text-critical" : "text-muted-foreground")}>
            {change === 0 ? "no change" : `${change > 0 ? "▲ +" : "▼ −"}${fmt(Math.abs(change))}`} <span className="font-normal text-muted-foreground">vs last week</span>
          </span>
        )}
      </div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      {trend && <Sparkline values={trend.values} days={trend.days} label={typeof label === "string" ? label : "Trend"} format={fmt} />}
    </>
  );
  const cls = "block rounded-lg border bg-card p-4 shadow-sm";
  return to ? <Link to={to} className={cn(cls, "transition-colors hover:border-primary/40 hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring")}>{body}</Link> : <div className={cls}>{body}</div>;
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
      <div className="mb-2 flex items-center justify-between">
        <H className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{title}</H>
        {action}
      </div>
      {children}
    </section>
  );
}
