import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, Clock, Pencil, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople, useUnsavedGuard, useUrlFilter } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet } from "@/components/ui/dialog";
import { Field, Textarea, Input } from "@/components/ui/input";
import { KeyValue, PageHeader, Section, Skeleton, Stat, Tooltip } from "@/components/ui/misc";
import { Markdown } from "@/components/Markdown";
import { Select } from "@/components/ui/select";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";

export const CONTROL_STATUS = [
  { value: "not_started", label: "Not started" },
  { value: "planned", label: "Planned" },
  { value: "partial", label: "Partially implemented" },
  { value: "implemented", label: "Implemented" },
  { value: "not_applicable", label: "Not applicable" },
];

const FLAGS = [
  { value: "no_evidence", label: "No current evidence" },
  { value: "review_overdue", label: "Review overdue" },
];

export default function Controls() {
  const { data, isLoading } = useApi<any[]>("/controls");
  const { can } = useAuth();
  const { people, name } = usePeople();
  // Filters live in the URL so the dashboard can link to them and a filtered view can be shared.
  const [domain, setDomain] = useUrlFilter("domain");
  const [status, setStatus] = useUrlFilter("status");
  const [owner, setOwner] = useUrlFilter("owner");
  const [flag, setFlag] = useUrlFilter("flag");
  const [open, setOpen] = useUrlFilter("open");
  const [selected, setSelected] = useState<Set<string | number>>(new Set());
  const rows = useMemo(() => (data ?? []).filter((c) =>
    (!domain || c.domain === domain) && (!status || c.status === status)
    && (!owner || (owner === "none" ? !c.owner_id && c.status !== "not_applicable" : String(c.owner_id) === owner))
    && (!flag || (flag === "no_evidence" ? c.needs_evidence : c.review_overdue))), [data, domain, status, owner, flag]);
  if (isLoading || !data) return <Skeleton className="h-96" />;
  const counts = (s: string) => data.filter((c) => c.status === s).length;
  const domains = [...new Set(data.map((c) => c.domain))];
  const editable = can("control.write");
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ShieldCheck} title="Controls" description="Keystone's common controls. Each one counts towards every framework it maps to." />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-5">
        <Stat label="Implemented" value={counts("implemented")} tone="good" to="/controls?status=implemented" />
        <Stat label="Partial" value={counts("partial")} tone="warning" to="/controls?status=partial" />
        <Stat label="Planned" value={counts("planned")} to="/controls?status=planned" />
        <Stat label="Not started" value={counts("not_started")} to="/controls?status=not_started" />
        <Stat label="No current evidence" value={data.filter((c) => c.needs_evidence).length} tone={data.some((c) => c.needs_evidence) ? "critical" : undefined} hint="Implemented, but nothing proves it today" to="/controls?flag=no_evidence" />
      </div>
      <DataTable
        rows={rows}
        rowKey={(c: any) => c.id}
        rowLabel={(c: any) => `${c.code} ${c.title}`}
        onRowClick={(c: any) => setOpen(String(c.id))}
        search={(c: any) => `${c.code} ${c.title} ${c.domain}`}
        selected={editable ? selected : undefined}
        onSelectedChange={editable ? setSelected : undefined}
        bulkBar={(ids) => <BulkControls ids={ids as number[]} people={people} onDone={() => setSelected(new Set())} />}
        toolbar={
          <>
            <div className="w-44"><Select value={domain} onChange={setDomain} allowEmpty emptyLabel="All domains" placeholder="All domains" options={domains.map((d) => ({ value: d, label: d }))} ariaLabel="Domain" /></div>
            <div className="w-48"><Select value={status} onChange={setStatus} allowEmpty emptyLabel="All statuses" placeholder="All statuses" options={CONTROL_STATUS} ariaLabel="Status" /></div>
            <div className="w-44"><Select value={owner} onChange={setOwner} allowEmpty emptyLabel="Any owner" placeholder="Any owner" options={[{ value: "none", label: "No owner" }, ...people.map((p) => ({ value: String(p.id), label: p.display_name }))]} ariaLabel="Owner" /></div>
            <div className="w-48"><Select value={flag} onChange={setFlag} allowEmpty emptyLabel="Any attention" placeholder="Needs attention" options={FLAGS} ariaLabel="Needs attention" /></div>
          </>
        }
        columns={[
          { key: "code", header: "Code", cell: (c: any) => <span className="font-mono text-xs">{c.code}</span>, sort: (c: any) => c.code, className: "w-28" },
          { key: "title", header: "Control", cell: (c: any) => <div><div className="font-medium">{c.title}</div><div className="text-xs text-muted-foreground">{c.domain}</div></div>, sort: (c: any) => c.title },
          { key: "fw", header: "Frameworks", cell: (c: any) => <div className="flex flex-wrap gap-1">{Object.keys(c.frameworks).map((f) => <Badge key={f} tone="outline">{f.split("_")[0]}</Badge>)}</div> },
          { key: "owner", header: "Owner", cell: (c: any) => c.owner_id ? name(c.owner_id) : <span className="whitespace-nowrap text-muted-foreground">No owner</span>, sort: (c: any) => (c.owner_id ? name(c.owner_id) : "~") },
          { key: "ready", header: "Readiness", cell: (c: any) => c.readiness === null ? <span className="text-muted-foreground">n/a</span> : <span>{c.readiness}%</span>, sort: (c: any) => c.readiness ?? -1, className: "w-24" },
          { key: "ev", header: "Evidence", sort: (c: any) => c.evidence_current, className: "w-44", cell: (c: any) => (
            <div className="flex flex-col gap-1">
              <span>{c.evidence_current ? `${c.evidence_current} current` : <span className="text-muted-foreground">None current</span>}</span>
              {c.needs_evidence && <span className="inline-flex items-center gap-1 text-xs font-medium text-critical"><AlertTriangle className="size-3.5" aria-hidden />Needed: implemented</span>}
              {c.review_overdue && <span className="inline-flex items-center gap-1 text-xs font-medium text-[#8a5a00] dark:text-warning"><Clock className="size-3.5" aria-hidden />Review overdue</span>}
            </div>
          ) },
          { key: "status", header: "Status", cell: (c: any) => <StatusBadge status={c.status} label={c.status_label} />, sort: (c: any) => c.status },
        ]}
      />
      {open && <ControlDrawer id={Number(open)} onClose={() => setOpen(null)} />}
    </div>
  );
}

function BulkControls({ ids, people, onDone }: { ids: number[]; people: { id: number; display_name: string }[]; onDone: () => void }) {
  const [owner, setOwner] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const run = useAction((body: any) => api<{ updated: number }>("/controls/bulk", { method: "POST", body }), {
    success: (r) => `${r.updated} control${r.updated === 1 ? "" : "s"} updated.`, invalidate: ["/controls", "/frameworks", "/dashboard", "/soa"], onSuccess: onDone,
  });
  const body: any = { ids };
  if (owner) body.owner_id = owner === "none" ? null : Number(owner);
  if (status) body.status = status;
  return (
    <>
      <div className="w-48"><Select value={owner} onChange={setOwner} allowEmpty emptyLabel="Keep owner" placeholder="Set owner…" options={[{ value: "none", label: "Remove owner" }, ...people.map((p) => ({ value: String(p.id), label: p.display_name }))]} ariaLabel="Set owner for selected controls" /></div>
      <div className="w-48"><Select value={status} onChange={setStatus} allowEmpty emptyLabel="Keep status" placeholder="Set status…" options={CONTROL_STATUS.filter((s) => s.value !== "not_applicable")} ariaLabel="Set status for selected controls" /></div>
      <Button size="sm" disabled={!owner && !status} loading={run.isPending} onClick={() => run.mutate(body)}>Apply to {ids.length}</Button>
    </>
  );
}

function ControlDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { can } = useAuth();
  const { people, name } = usePeople();
  const { data } = useApi<any>(`/controls/${id}`);
  const ready = useApi<any>(`/controls/${id}/readiness`);
  const [f, setF] = useState<any>(null);
  const [editing, setEditing] = useState(false);
  const initial = (d: any) => ({ status: d.status, owner_id: d.owner_id, implementation_notes: d.implementation_notes ?? "", na_justification: d.na_justification ?? "", review_interval_days: d.review_interval_days });
  useEffect(() => { if (data) setF(initial(data)); }, [data]);
  const dirty = editing && !!data && !!f && JSON.stringify(f) !== JSON.stringify(initial(data));
  const confirmDiscard = useUnsavedGuard(dirty);
  const save = useAction((body: any) => api(`/controls/${id}`, { method: "PATCH", body }), { success: "Control saved.", invalidate: ["/controls", "/frameworks", "/dashboard", "/soa"], onSuccess: () => setEditing(false) });
  const review = useAction(() => api(`/controls/${id}/review`, { method: "POST" }), { success: "Review recorded.", invalidate: ["/controls"] });
  const editable = can("control.write");
  const statusLabel = (v: string) => CONTROL_STATUS.find((s) => s.value === v)?.label ?? v;
  return (
    <Sheet open onOpenChange={(o) => { if (!o && confirmDiscard()) onClose(); }} title={data ? `${data.code} · ${data.title}` : "Loading…"} subtitle={data?.domain}
      actions={editable && data && !editing && <Button size="sm" variant="outline" onClick={() => setEditing(true)}><Pencil /> Edit</Button>}>
      {!data || !f ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <p className="text-sm">{data.description}</p>
          {ready.data && (
            <Section title={`Audit readiness · ${ready.data.score}%`}>
              <ul className="space-y-1.5">
                {ready.data.checks.map((c: any) => <li key={c.kind} className="flex items-center gap-2 text-sm">{c.ok ? <CheckCircle2 className="size-4 text-good" aria-label="Met" /> : <AlertTriangle className="size-4 text-warning" aria-label="Not met" />}{c.label}</li>)}
                {ready.data.status === "not_applicable" && <li className="text-sm text-muted-foreground">Not applicable.</li>}
              </ul>
              {ready.data.tasks.length > 0 && (
                <div className="mt-3 divide-y rounded-md border">
                  {ready.data.tasks.slice(0, 6).map((t: any) => <Link key={t.id} to={`/tasks?open=${t.id}`} className="flex items-center justify-between gap-2 px-3 py-2 text-sm hover:bg-muted/50"><span className="truncate">{t.title}</span><span className="flex items-center gap-2 text-xs text-muted-foreground">{fmtDate(t.due_date)}<StatusBadge status={t.overdue ? "overdue" : t.status} /></span></Link>)}
                </div>
              )}
            </Section>
          )}
          <Section title="Implementation">
            {!editing ? (
              <>
                <KeyValue items={[
                  ["Status", <StatusBadge key="s" status={data.status} label={statusLabel(data.status)} />],
                  ["Owner", data.owner_id ? name(data.owner_id) : "No owner"],
                  ["Review every", `${data.review_interval_days} days`],
                  ["Last reviewed", fmtDate(data.last_reviewed_at)],
                  ["Next review", fmtDate(data.next_review_date)],
                  ...(data.status === "not_applicable" ? [["Why not applicable", data.na_justification] as [string, string]] : []),
                ]} />
                <div className="mt-4 text-sm">
                  <div className="mb-1 font-medium">How it is implemented</div>
                  {data.implementation_notes ? <Markdown>{data.implementation_notes}</Markdown> : <p className="text-muted-foreground">Not described yet.</p>}
                </div>
                {editable && <div className="mt-4"><Button variant="outline" loading={review.isPending} onClick={() => review.mutate(undefined)}><CheckCircle2 /> Record review</Button></div>}
              </>
            ) : (
              <>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Status"><Select value={f.status} onChange={(v) => setF({ ...f, status: v })} options={CONTROL_STATUS} /></Field>
                  <Field label="Owner"><Select value={f.owner_id ? String(f.owner_id) : null} onChange={(v) => setF({ ...f, owner_id: v ? Number(v) : null })} allowEmpty emptyLabel="No owner" options={people.map((p) => ({ value: String(p.id), label: p.display_name }))} /></Field>
                </div>
                <Field className="mt-4" label="How it is implemented"><Textarea value={f.implementation_notes} onChange={(e) => setF({ ...f, implementation_notes: e.target.value })} /></Field>
                {f.status === "not_applicable" && <Field className="mt-4" label="Why not applicable" required><Textarea value={f.na_justification} onChange={(e) => setF({ ...f, na_justification: e.target.value })} /></Field>}
                <Field className="mt-4 max-w-xs" label="Review every (days)"><Input type="number" min={30} max={1095} value={f.review_interval_days} onChange={(e) => setF({ ...f, review_interval_days: Number(e.target.value) })} /></Field>
                <div className="mt-4 flex gap-2">
                  <Button loading={save.isPending} disabled={!dirty} onClick={() => save.mutate({ ...f, implementation_notes: f.implementation_notes || null, na_justification: f.na_justification || null })}>Save</Button>
                  <Button variant="ghost" onClick={() => { if (confirmDiscard()) { setF(initial(data)); setEditing(false); } }}>Cancel</Button>
                </div>
              </>
            )}
          </Section>
          <Section title="Satisfies">
            <div className="space-y-3">
              {Object.entries(data.requirements).map(([fw, reqs]: any) => (
                <div key={fw}>
                  <div className="mb-1 text-xs font-medium text-muted-foreground">{fw}</div>
                  <div className="flex flex-wrap gap-1">{reqs.map((r: any) => <Tooltip key={r.ref} content={r.title}><span><Badge tone="primary" className="font-mono">{r.ref}</Badge></span></Tooltip>)}</div>
                </div>
              ))}
            </div>
          </Section>
          <Section title={`Evidence (${data.evidence.length})`} action={can("evidence.write") && <Link to={`/evidence?control=${id}`} className="text-sm text-primary hover:underline">Add evidence</Link>}>
            {data.evidence.length === 0 ? <p className="text-sm text-muted-foreground">No evidence yet.</p> : (
              <ul className="divide-y rounded-md border">
                {data.evidence.map((e: any) => (
                  <li key={e.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                    <span className="min-w-0 truncate">{e.title}</span>
                    <span className="flex items-center gap-2 text-xs text-muted-foreground">{e.valid_until && `until ${fmtDate(e.valid_until)}`}<StatusBadge status={e.state} /></span>
                  </li>
                ))}
              </ul>
            )}
          </Section>
          {data.risks.length > 0 && (
            <Section title="Treats risks">
              <div className="flex flex-wrap gap-2">{data.risks.map((r: any) => <Link key={r.id} to={`/risks?open=${r.id}`}><Badge tone="outline">{r.ref} {r.title}</Badge></Link>)}</div>
            </Section>
          )}
        </div>
      )}
    </Sheet>
  );
}
