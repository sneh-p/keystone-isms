import { useMemo, useState } from "react";
import { Link } from "react-router";
import { CalendarDays, ChevronLeft, ChevronRight } from "lucide-react";
import { useApi, usePeople } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { PageHeader, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";

// Categorical slots 1-8 in fixed order from the dataviz reference palette, validated with its validator in light
// (on #ffffff) and dark (on #18181b) mode. More kinds than slots, so kinds fold into eight groups (never a ninth hue);
// each event still names its own kind. Kind is never shown by colour alone: legend, tooltip and screen-reader label.
const GROUPS: Record<string, { label: string; dot: string }> = {
  work: { label: "Tasks and actions", dot: "bg-[#2a78d6] dark:bg-[#3987e5]" },
  control: { label: "Control reviews", dot: "bg-[#eb6834] dark:bg-[#d95926]" },
  policy: { label: "Policies and objectives", dot: "bg-[#1baf7a] dark:bg-[#199e70]" },
  risk: { label: "Risk reviews", dot: "bg-[#eda100] dark:bg-[#c98500]" },
  vendor: { label: "Vendors and contracts", dot: "bg-[#e87ba4] dark:bg-[#d55181]" },
  privacy: { label: "Privacy and continuity", dot: "bg-[#008300] dark:bg-[#0ca30c]" },
  evidence: { label: "Evidence and configuration", dot: "bg-[#6250d6] dark:bg-[#9085e9]" },
  audit: { label: "Audits and access reviews", dot: "bg-[#e34948] dark:bg-[#e66767]" },
};
const KINDS: Record<string, { label: string; group: keyof typeof GROUPS }> = {
  task: { label: "Task", group: "work" },
  nc_due: { label: "Nonconformity due", group: "work" },
  corrective_action: { label: "Corrective action", group: "work" },
  control_review: { label: "Control review", group: "control" },
  policy_review: { label: "Policy review", group: "policy" },
  objective: { label: "Objective target", group: "policy" },
  risk_review: { label: "Risk review", group: "risk" },
  vendor_review: { label: "Vendor review", group: "vendor" },
  contract_end: { label: "Contract end", group: "vendor" },
  dsr_due: { label: "Data subject request", group: "privacy" },
  privacy_review: { label: "Processing activity review", group: "privacy" },
  dpia_review: { label: "DPIA review", group: "privacy" },
  bia_review: { label: "Business impact review", group: "privacy" },
  continuity_test: { label: "Continuity test", group: "privacy" },
  plan_exercise: { label: "Plan exercise due", group: "privacy" },
  evidence_expiry: { label: "Evidence expiry", group: "evidence" },
  firewall_upload: { label: "Firewall configuration out of date", group: "evidence" },
  audit: { label: "Audit", group: "audit" },
  access_review: { label: "Access review", group: "audit" },
};
const kindStyle = (kind: string) => {
  const k = KINDS[kind];
  return k ? { label: k.label, dot: GROUPS[k.group].dot } : { label: kind, dot: "bg-muted-foreground" };
};

const iso = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;

/** Compliance calendar: tests, reviews, renewals and audits by date, from the records' own dates. */
export default function CalendarPage() {
  const now = new Date();
  const [month, setMonth] = useState(new Date(now.getFullYear(), now.getMonth(), 1));
  const [owner, setOwner] = useState<string | null>(null);
  const [kind, setKind] = useState<string | null>(null);
  const { people, name } = usePeople();
  const first = month, last = new Date(month.getFullYear(), month.getMonth() + 1, 0);
  const { data } = useApi<any[]>(`/calendar?start=${iso(first)}&end=${iso(last)}`);
  const events = useMemo(() => (data ?? []).filter((e) => (!owner || String(e.owner_id) === owner) && (!kind || e.kind === kind)), [data, owner, kind]);
  const byDay = useMemo(() => {
    const m = new Map<string, any[]>();
    for (const e of events) m.set(e.date, [...(m.get(e.date) ?? []), e]);
    return m;
  }, [events]);
  const lead = (first.getDay() + 6) % 7; // weeks start on Monday
  const cells = [...Array(lead).fill(null), ...Array.from({ length: last.getDate() }, (_, i) => new Date(month.getFullYear(), month.getMonth(), i + 1))];
  const today = iso(now);
  const title = month.toLocaleDateString(undefined, { month: "long", year: "numeric" });
  return (
    <div className="animate-fade-in">
      <PageHeader icon={CalendarDays} title="Calendar" description="Who tests, reviews or renews what, and when. Dates come from tasks, reviews, contracts, evidence and audits; change the record to move an entry." />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Button variant="outline" size="icon" aria-label="Previous month" onClick={() => setMonth(new Date(month.getFullYear(), month.getMonth() - 1, 1))}><ChevronLeft /></Button>
        <h2 className="w-44 text-center text-base font-semibold" aria-live="polite">{title}</h2>
        <Button variant="outline" size="icon" aria-label="Next month" onClick={() => setMonth(new Date(month.getFullYear(), month.getMonth() + 1, 1))}><ChevronRight /></Button>
        <Button variant="ghost" size="sm" onClick={() => setMonth(new Date(now.getFullYear(), now.getMonth(), 1))}>Today</Button>
        <div className="ml-auto flex flex-wrap gap-2">
          <div className="w-48"><Select value={owner} onChange={setOwner} allowEmpty emptyLabel="Everyone" placeholder="Person" ariaLabel="Person" options={people.map((p) => ({ value: String(p.id), label: p.display_name }))} /></div>
          <div className="w-48"><Select value={kind} onChange={setKind} allowEmpty emptyLabel="All kinds" placeholder="Kind" ariaLabel="Kind" options={Object.entries(KINDS).map(([k, v]) => ({ value: k, label: v.label }))} /></div>
        </div>
      </div>
      <ul className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-label="Legend">
        {Object.entries(GROUPS).map(([k, v]) => <li key={k} className="flex items-center gap-1.5"><span className={cn("size-2 rounded-full", v.dot)} aria-hidden />{v.label}</li>)}
      </ul>
      {!data ? <Skeleton className="h-[32rem]" /> : (
        <>
          <div className="hidden grid-cols-7 overflow-hidden rounded-lg border bg-border md:grid" style={{ gap: "1px" }}>
            {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => <div key={d} className="bg-muted/60 px-2 py-1.5 text-xs font-medium text-muted-foreground">{d}</div>)}
            {cells.map((d, i) => {
              const key = d ? iso(d) : `x${i}`;
              const items = d ? byDay.get(key) ?? [] : [];
              return (
                <div key={key} className={cn("min-h-28 bg-card p-1.5", !d && "bg-muted/30")}>
                  {d && <div className={cn("mb-1 text-xs", key === today ? "inline-grid size-5 place-items-center rounded-full bg-primary font-semibold text-primary-foreground" : "text-muted-foreground")}>{d.getDate()}</div>}
                  <ul className="space-y-0.5">
                    {items.slice(0, 4).map((e, j) => <EventLink key={j} e={e} name={name} compact />)}
                    {items.length > 4 && <li className="px-1 text-[11px] text-muted-foreground">+{items.length - 4} more</li>}
                  </ul>
                </div>
              );
            })}
          </div>
          <div className="space-y-3 md:hidden">
            {[...byDay.entries()].map(([day, items]) => (
              <section key={day} className="rounded-lg border bg-card p-3">
                <h3 className="mb-1 text-sm font-medium">{new Date(day + "T00:00").toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" })}</h3>
                <ul className="space-y-1">{items.map((e, j) => <EventLink key={j} e={e} name={name} />)}</ul>
              </section>
            ))}
            {byDay.size === 0 && <p className="text-sm text-muted-foreground">Nothing scheduled this month.</p>}
          </div>
        </>
      )}
    </div>
  );
}

function EventLink({ e, name, compact }: { e: any; name: (id?: number | null) => string; compact?: boolean }) {
  const k = kindStyle(e.kind);
  return (
    <li>
      <Link to={e.page} title={`${k.label}: ${e.title}${e.owner_id ? ` · ${name(e.owner_id)}` : ""}`}
        className={cn("flex items-start gap-1.5 rounded px-1 py-0.5 hover:bg-muted", compact ? "text-[11px] leading-snug" : "text-sm", e.done && "line-through opacity-60")}>
        <span className={cn("mt-1 size-1.5 shrink-0 rounded-full", k.dot)} aria-hidden />
        <span className={cn("min-w-0", compact && "line-clamp-2")}>
          <span className="sr-only">{k.label}: </span>
          {e.overdue && <span className="font-medium text-critical">Overdue · </span>}{e.title}
          {!compact && e.owner_id && <span className="text-muted-foreground"> · {name(e.owner_id)}</span>}
        </span>
      </Link>
    </li>
  );
}
