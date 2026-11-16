import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, CheckCircle2, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet } from "@/components/ui/dialog";
import { Field, Textarea, Input } from "@/components/ui/input";
import { KeyValue, PageHeader, Section, Skeleton, Stat, Tooltip } from "@/components/ui/misc";
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

export default function Controls() {
  const { data, isLoading } = useApi<any[]>("/controls");
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const [domain, setDomain] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const open = params.get("open");
  const rows = useMemo(() => (data ?? []).filter((c) => (!domain || c.domain === domain) && (!status || c.status === status)), [data, domain, status]);
  if (isLoading || !data) return <Skeleton className="h-96" />;
  const counts = (s: string) => data.filter((c) => c.status === s).length;
  const domains = [...new Set(data.map((c) => c.domain))];
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ShieldCheck} title="Controls" description="Keystone's common controls. Each one counts towards every framework it maps to." />
      <div className="mb-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Implemented" value={counts("implemented")} tone="good" />
        <Stat label="Partial" value={counts("partial")} tone="warning" />
        <Stat label="Planned" value={counts("planned")} />
        <Stat label="Not started" value={counts("not_started")} />
        <Stat label="Need evidence" value={data.filter((c) => c.needs_evidence).length} tone={data.some((c) => c.needs_evidence) ? "critical" : undefined} hint="Implemented without current evidence" />
      </div>
      <DataTable
        rows={rows}
        rowKey={(c: any) => c.id}
        onRowClick={(c: any) => setParams({ open: String(c.id) })}
        search={(c: any) => `${c.code} ${c.title} ${c.domain}`}
        toolbar={
          <>
            <div className="w-44"><Select value={domain} onChange={setDomain} allowEmpty emptyLabel="All domains" placeholder="All domains" options={domains.map((d) => ({ value: d, label: d }))} ariaLabel="Domain" /></div>
            <div className="w-52"><Select value={status} onChange={setStatus} allowEmpty emptyLabel="All statuses" placeholder="All statuses" options={CONTROL_STATUS} ariaLabel="Status" /></div>
          </>
        }
        columns={[
          { key: "code", header: "Code", cell: (c: any) => <span className="font-mono text-xs">{c.code}</span>, sort: (c: any) => c.code, className: "w-28" },
          { key: "title", header: "Control", cell: (c: any) => <div><div className="font-medium">{c.title}</div><div className="text-xs text-muted-foreground">{c.domain}</div></div>, sort: (c: any) => c.title },
          { key: "fw", header: "Frameworks", cell: (c: any) => <div className="flex flex-wrap gap-1">{Object.keys(c.frameworks).map((f) => <Badge key={f} tone="outline">{f.split("_")[0]}</Badge>)}</div> },
          { key: "owner", header: "Owner", cell: (c: any) => name(c.owner_id), sort: (c: any) => name(c.owner_id) },
          { key: "flags", header: "", cell: (c: any) => <div className="flex gap-1">{c.needs_evidence && <Tooltip content="Implemented without current evidence"><AlertTriangle className="size-4 text-critical" /></Tooltip>}{c.review_overdue && <Tooltip content="Review overdue"><AlertTriangle className="size-4 text-warning" /></Tooltip>}</div>, className: "w-12" },
          { key: "status", header: "Status", cell: (c: any) => <StatusBadge status={c.status} label={c.status_label} />, sort: (c: any) => c.status },
        ]}
      />
      {open && <ControlDrawer id={Number(open)} onClose={() => setParams({})} />}
    </div>
  );
}

function ControlDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { can } = useAuth();
  const { people, name } = usePeople();
  const { data } = useApi<any>(`/controls/${id}`);
  const ready = useApi<any>(`/controls/${id}/readiness`);
  const [f, setF] = useState<any>(null);
  useEffect(() => {
    if (data) setF({ status: data.status, owner_id: data.owner_id, implementation_notes: data.implementation_notes ?? "", na_justification: data.na_justification ?? "", review_interval_days: data.review_interval_days });
  }, [data]);
  const save = useAction((body: any) => api(`/controls/${id}`, { method: "PATCH", body }), { success: "Control saved.", invalidate: ["/controls", "/frameworks", "/dashboard", "/soa"] });
  const review = useAction(() => api(`/controls/${id}/review`, { method: "POST" }), { success: "Review recorded.", invalidate: ["/controls"] });
  const editable = can("control.write");
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data ? `${data.code} · ${data.title}` : "Loading…"} subtitle={data?.domain}>
      {!data || !f ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <p className="text-sm">{data.description}</p>
          {ready.data && (
            <Section title={`Audit readiness · ${ready.data.score}%`}>
              <ul className="space-y-1.5">
                {ready.data.checks.map((c: any) => <li key={c.kind} className="flex items-center gap-2 text-sm">{c.ok ? <CheckCircle2 className="size-4 text-good" /> : <AlertTriangle className="size-4 text-warning" />}{c.label}</li>)}
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
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Status"><Select value={f.status} onChange={(v) => setF({ ...f, status: v })} options={CONTROL_STATUS} disabled={!editable} /></Field>
              <Field label="Owner"><Select value={f.owner_id ? String(f.owner_id) : null} onChange={(v) => setF({ ...f, owner_id: v ? Number(v) : null })} allowEmpty emptyLabel="Unassigned" options={people.map((p) => ({ value: String(p.id), label: p.display_name }))} disabled={!editable} /></Field>
            </div>
            <Field className="mt-4" label="How it is implemented"><Textarea value={f.implementation_notes} onChange={(e) => setF({ ...f, implementation_notes: e.target.value })} disabled={!editable} /></Field>
            {f.status === "not_applicable" && <Field className="mt-4" label="Why not applicable" required><Textarea value={f.na_justification} onChange={(e) => setF({ ...f, na_justification: e.target.value })} disabled={!editable} /></Field>}
            <Field className="mt-4 max-w-xs" label="Review every (days)"><Input type="number" min={30} max={1095} value={f.review_interval_days} onChange={(e) => setF({ ...f, review_interval_days: Number(e.target.value) })} disabled={!editable} /></Field>
            {editable && (
              <div className="mt-4 flex gap-2">
                <Button loading={save.isPending} onClick={() => save.mutate({ ...f, implementation_notes: f.implementation_notes || null, na_justification: f.na_justification || null })}>Save</Button>
                <Button variant="outline" loading={review.isPending} onClick={() => review.mutate(undefined)}><CheckCircle2 /> Record review</Button>
              </div>
            )}
            <div className="mt-4"><KeyValue items={[["Last reviewed", fmtDate(data.last_reviewed_at)], ["Next review", fmtDate(data.next_review_date)], ["Owner", name(data.owner_id)]]} /></div>
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
          <Section title={`Evidence (${data.evidence.length})`} action={<Link to={`/evidence?control=${id}`} className="text-sm text-primary hover:underline">Add evidence</Link>}>
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
