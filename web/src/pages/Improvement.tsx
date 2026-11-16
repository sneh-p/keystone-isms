import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CheckCircle2, ClipboardCheck, Plus, RefreshCw, Search, Stamp, Wrench } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { KeyValue, PageHeader, Progress, Section, Skeleton, Stat } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { clean, DateInput, EnumSelect, OwnerSelect } from "@/components/forms";

const NC_SOURCES = ["internal_audit", "external_audit", "incident", "management_review", "self_identified", "complaint", "monitoring"];
const SEV_TONE: Record<string, any> = { major: "critical", minor: "warning", observation: "neutral" };

// ---- Nonconformities ------------------------------------------------------------------------

export function Nonconformities() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any>("/nonconformities");
  const controls = useApi<any[]>("/controls");
  const [raise, setRaise] = useState<any>(null);
  const doRaise = useAction((b: any) => api("/nonconformities", { body: b }), { success: "Nonconformity raised.", invalidate: ["/nonconformities", "/dashboard"], onSuccess: () => setRaise(null) });
  if (!data) return <Skeleton className="h-96" />;
  const att = data.attention;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Wrench} title="Nonconformities & corrective actions" description="React, find the root cause, act, and check the action worked (ISO 27001 10.2)."
        actions={(can("nc.write") || can("audit.findings")) && <Button onClick={() => setRaise({ title: "", source: "self_identified", severity: "minor", description: "", common_control_id: null, due_date: null })}><Plus /> Raise nonconformity</Button>} />
      <div className="mb-5 grid gap-4 sm:grid-cols-4">
        <Stat label="Open" value={data.items.filter((n: any) => n.status !== "closed").length} />
        <Stat label="Overdue" value={att.overdue.length} tone={att.overdue.length ? "critical" : undefined} />
        <Stat label="Actions overdue" value={att.actions_overdue.length} tone={att.actions_overdue.length ? "warning" : undefined} />
        <Stat label="Awaiting effectiveness check" value={att.awaiting_verification.length} />
      </div>
      <DataTable rows={data.items} rowKey={(n: any) => n.id} onRowClick={(n: any) => setParams({ open: String(n.id) })} search={(n: any) => n.title} columns={[
        { key: "t", header: "Nonconformity", cell: (n: any) => <div><div className="font-medium">{n.title}</div><div className="text-xs text-muted-foreground">{titleCase(n.source)} · {name(n.owner_id)}</div></div> },
        { key: "s", header: "Severity", cell: (n: any) => <Badge tone={SEV_TONE[n.severity]}>{titleCase(n.severity)}</Badge> },
        { key: "st", header: "Status", cell: (n: any) => <StatusBadge status={n.status} />, sort: (n: any) => n.status },
        { key: "a", header: "Actions", cell: (n: any) => `${n.actions.filter((a: any) => a.status === "verified").length}/${n.actions.length} verified` },
        { key: "d", header: "Due", cell: (n: any) => <span className={att.overdue.includes(n.id) ? "font-medium text-critical" : ""}>{fmtDate(n.due_date)}</span>, sort: (n: any) => n.due_date ?? "" },
      ]} />
      <Dialog open={!!raise} onOpenChange={(o) => !o && setRaise(null)} title="Raise a nonconformity" wide footer={<Button loading={doRaise.isPending} onClick={() => doRaise.mutate(clean({ ...raise, common_control_id: raise.common_control_id ? Number(raise.common_control_id) : null }))}>Raise</Button>}>
        {raise && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Nonconformity" required className="sm:col-span-2"><Input value={raise.title} onChange={(e) => setRaise({ ...raise, title: e.target.value })} /></Field>
          <Field label="Source"><EnumSelect value={raise.source} onChange={(v) => setRaise({ ...raise, source: v })} values={NC_SOURCES} /></Field>
          <Field label="Severity"><EnumSelect value={raise.severity} onChange={(v) => setRaise({ ...raise, severity: v })} values={["major", "minor", "observation"]} /></Field>
          <Field label="Related control"><Select value={raise.common_control_id} onChange={(v) => setRaise({ ...raise, common_control_id: v })} allowEmpty options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} /></Field>
          <Field label="Target closure"><DateInput value={raise.due_date} onChange={(v) => setRaise({ ...raise, due_date: v })} /></Field>
          <Field label="Description and evidence" className="sm:col-span-2"><Textarea value={raise.description} onChange={(e) => setRaise({ ...raise, description: e.target.value })} /></Field>
        </div>}
      </Dialog>
      {params.get("open") && <NcDrawer nc={data.items.find((n: any) => String(n.id) === params.get("open"))} onClose={() => setParams({})} />}
    </div>
  );
}

function NcDrawer({ nc, onClose }: { nc: any; onClose: () => void }) {
  const { can, me } = useAuth();
  const { name } = usePeople();
  const [an, setAn] = useState({ containment: nc?.containment ?? "", root_cause: nc?.root_cause ?? "", owner_id: nc?.owner_id ?? null });
  const [ca, setCa] = useState<any>({ description: "", owner_id: null, due_date: null });
  const [done, setDone] = useState<Record<number, string>>({});
  const [ver, setVer] = useState<Record<number, string>>({});
  const inv = ["/nonconformities", "/dashboard"];
  const save = useAction(() => api(`/nonconformities/${nc.id}`, { method: "PATCH", body: clean(an) }), { success: "Saved.", invalidate: inv });
  const add = useAction(() => api(`/nonconformities/${nc.id}/actions`, { body: clean(ca) }), { success: "Action added.", invalidate: inv, onSuccess: () => setCa({ description: "", owner_id: null, due_date: null }) });
  const plan = useAction(() => api(`/nonconformities/${nc.id}/plan`, { method: "POST" }), { success: "Action plan recorded.", invalidate: inv });
  const complete = useAction((aid: number) => api(`/corrective-actions/${aid}/complete`, { body: { notes: done[aid] ?? "" } }), { success: "Action completed.", invalidate: inv });
  const verify = useAction((v: { aid: number; ok: boolean }) => api(`/corrective-actions/${v.aid}/verify`, { body: { effective: v.ok, notes: ver[v.aid] ?? "" } }), { success: "Effectiveness check recorded.", invalidate: inv });
  const close = useAction(() => api(`/nonconformities/${nc.id}/close`, { method: "POST" }), { success: "Nonconformity closed.", invalidate: inv });
  if (!nc) return null;
  const ed = can("nc.write") && nc.status !== "closed";
  const steps = ["open", "action_planned", "verification", "closed"];
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={nc.title} subtitle={<span className="flex items-center gap-2"><StatusBadge status={nc.status} /><Badge tone={SEV_TONE[nc.severity]}>{nc.severity}</Badge>{titleCase(nc.source)}</span>}
      actions={nc.status === "verification" && can("nc.verify") && <Button size="sm" onClick={() => close.mutate(undefined)}><CheckCircle2 /> Close</Button>}>
      <div className="space-y-6">
        <ol className="grid grid-cols-4 gap-2 text-center text-xs">
          {steps.map((s, i) => <li key={s} className={`rounded-md border px-2 py-1.5 ${steps.indexOf(nc.status) >= i ? "border-primary bg-accent font-medium text-accent-foreground" : "text-muted-foreground"}`}>{i + 1}. {titleCase(s)}</li>)}
        </ol>
        {nc.description && <p className="whitespace-pre-wrap text-sm">{nc.description}</p>}
        <Section title="Analysis">
          <div className="space-y-3">
            <Field label="Immediate containment / correction"><Textarea value={an.containment} onChange={(e) => setAn({ ...an, containment: e.target.value })} disabled={!ed} /></Field>
            <Field label="Root cause"><Textarea value={an.root_cause} onChange={(e) => setAn({ ...an, root_cause: e.target.value })} disabled={!ed} /></Field>
            <Field label="Owner"><OwnerSelect value={an.owner_id} onChange={(v) => setAn({ ...an, owner_id: v })} disabled={!ed} /></Field>
            {ed && <div className="flex gap-2"><Button variant="outline" loading={save.isPending} onClick={() => save.mutate(undefined)}>Save analysis</Button>{nc.status === "open" && <Button loading={plan.isPending} onClick={() => plan.mutate(undefined)}>Move to action planned</Button>}</div>}
          </div>
        </Section>
        <Section title="Corrective actions">
          <div className="space-y-3">
            {nc.actions.map((a: any) => (
              <div key={a.id} className="rounded-lg border p-3 text-sm">
                <div className="flex items-start justify-between gap-2"><span>{a.description}</span><StatusBadge status={a.status === "verified" ? "done" : a.status === "ineffective" ? "fail" : a.status} label={titleCase(a.status)} /></div>
                <div className="mt-1 text-xs text-muted-foreground">{name(a.owner_id)} · due {fmtDate(a.due_date)}{a.completion_notes && ` · done: ${a.completion_notes}`}{a.effectiveness_notes && ` · check: ${a.effectiveness_notes}`}</div>
                {a.status === "open" && ed && <div className="mt-2 flex gap-2"><Input className="h-8" placeholder="What was done" value={done[a.id] ?? ""} onChange={(e) => setDone({ ...done, [a.id]: e.target.value })} /><Button size="sm" onClick={() => complete.mutate(a.id)}>Mark done</Button></div>}
                {a.status === "done" && can("nc.verify") && (a.owner_id === me?.id ? <p className="mt-2 text-xs text-muted-foreground">You own this action, so someone else must check it.</p> : (
                  <div className="mt-2 flex flex-wrap gap-2"><Input className="h-8 min-w-48 flex-1" placeholder="Evidence of effectiveness" value={ver[a.id] ?? ""} onChange={(e) => setVer({ ...ver, [a.id]: e.target.value })} /><Button size="sm" onClick={() => verify.mutate({ aid: a.id, ok: true })}>Effective</Button><Button size="sm" variant="outline" onClick={() => verify.mutate({ aid: a.id, ok: false })}>Not effective</Button></div>
                ))}
              </div>
            ))}
            {ed && (
              <div className="grid gap-2 rounded-lg border border-dashed p-3 sm:grid-cols-[2fr_1fr_1fr_auto] sm:items-end">
                <Field label="New action"><Input value={ca.description} onChange={(e) => setCa({ ...ca, description: e.target.value })} /></Field>
                <Field label="Owner"><OwnerSelect value={ca.owner_id} onChange={(v) => setCa({ ...ca, owner_id: v })} /></Field>
                <Field label="Due"><DateInput value={ca.due_date} onChange={(v) => setCa({ ...ca, due_date: v })} /></Field>
                <Button disabled={!ca.description} onClick={() => add.mutate(undefined)}>Add</Button>
              </div>
            )}
          </div>
        </Section>
      </div>
    </Sheet>
  );
}

// ---- Audits ------------------------------------------------------------------------------------

const FT: Record<string, [string, any]> = { major_nc: ["Major NC", "critical"], minor_nc: ["Minor NC", "warning"], observation: ["Observation", "neutral"], opportunity: ["Opportunity", "primary"], conformity: ["Conformity", "good"] };

export function Audits() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any>("/audits");
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Search} title="Audits" description="Internal audit programme (ISO 27001 9.2), plus external, certification and supplier audits." actions={can("audit.manage") && <Button onClick={() => setParams({ open: "new" })}><Plus /> Plan audit</Button>} />
      <div className="mb-5 grid gap-4 lg:grid-cols-[1fr_2fr]">
        <Card><CardBody>
          <div className="text-sm text-muted-foreground">Controls audited in the last 36 months</div>
          <div className="mt-1 text-3xl font-semibold">{data.coverage.pct}%</div>
          <Progress className="mt-3" value={data.coverage.pct} />
          <div className="mt-2 text-xs text-muted-foreground">{data.coverage.audited} of {data.coverage.applicable} applicable controls</div>
        </CardBody></Card>
        <Card><CardHeader title="Not yet audited" description="Plan these into the programme." /><CardBody className="flex max-h-40 flex-wrap gap-1 overflow-auto">{data.coverage.not_audited.map((c: string) => <Badge key={c} tone="outline">{c}</Badge>)}</CardBody></Card>
      </div>
      <DataTable rows={data.audits} rowKey={(a: any) => a.id} onRowClick={(a: any) => setParams({ open: String(a.id) })} search={(a: any) => a.title} columns={[
        { key: "t", header: "Audit", cell: (a: any) => <div><div className="font-medium">{a.title}</div><div className="text-xs text-muted-foreground">{titleCase(a.audit_type)} · lead {name(a.lead_auditor_id)}</div></div> },
        { key: "p", header: "Planned", cell: (a: any) => `${fmtDate(a.planned_start)}${a.planned_end ? ` – ${fmtDate(a.planned_end)}` : ""}`, sort: (a: any) => a.planned_start ?? "" },
        { key: "s", header: "Status", cell: (a: any) => <StatusBadge status={a.status} /> },
        { key: "c", header: "Controls", cell: (a: any) => a.controls.length, className: "text-right" },
        { key: "f", header: "Findings", cell: (a: any) => <div className="flex flex-wrap gap-1">{a.findings.map((f: any) => <Badge key={f.id} tone={FT[f.finding_type][1]}>{FT[f.finding_type][0]}</Badge>)}</div> },
      ]} />
      {params.get("open") && <AuditDrawer id={params.get("open")!} audits={data.audits} onClose={() => setParams({})} onCreated={(id) => setParams({ open: String(id) })} />}
    </div>
  );
}

function AuditDrawer({ id, audits, onClose, onCreated }: { id: string; audits: any[]; onClose: () => void; onCreated: (id: number) => void }) {
  const { can } = useAuth();
  const isNew = id === "new";
  const a = audits.find((x) => String(x.id) === id);
  const controls = useApi<any[]>("/controls");
  const [f, setF] = useState<any>(() => ({ title: a?.title ?? "", audit_type: a?.audit_type ?? "internal", lead_auditor_id: a?.lead_auditor_id ?? null, audit_team: a?.audit_team ?? "", planned_start: a?.planned_start ?? null, planned_end: a?.planned_end ?? null, scope: a?.scope ?? "", criteria: a?.criteria ?? "", summary: a?.summary ?? "", conclusion: a?.conclusion ?? "", control_ids: (a?.control_ids ?? []).map(String) }));
  const [fd, setFd] = useState<any>({ finding_type: "minor_nc", title: "", evidence: "", common_control_id: null });
  const inv = ["/audits", "/nonconformities", "/dashboard"];
  const save = useAction(() => (isNew ? api("/audits", { body: { ...clean(f), control_ids: f.control_ids.map(Number) } }) : api(`/audits/${id}`, { method: "PATCH", body: { ...clean(f), control_ids: f.control_ids.map(Number) } })), { success: "Audit saved.", invalidate: inv, onSuccess: (r: any) => isNew && onCreated(r.id) });
  const adv = useAction(() => api(`/audits/${id}/advance`, { method: "POST" }), { success: "Audit status updated.", invalidate: inv });
  const find = useAction(() => api(`/audits/${id}/findings`, { body: clean({ ...fd, common_control_id: fd.common_control_id ? Number(fd.common_control_id) : null }) }), { success: "Finding recorded.", invalidate: inv, onSuccess: () => setFd({ finding_type: "minor_nc", title: "", evidence: "", common_control_id: null }) });
  const ed = can("audit.manage") && a?.status !== "closed";
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={isNew ? "Plan an audit" : a?.title} subtitle={a && <StatusBadge status={a.status} />}
      actions={a && ed && a.next_status && <Button size="sm" loading={adv.isPending} onClick={() => adv.mutate(undefined)}>Move to {titleCase(a.next_status)}</Button>}>
      <div className="space-y-6">
        {a?.conflicts?.length > 0 && <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">Objectivity: the lead auditor owns in-scope controls {a.conflicts.join(", ")}.</p>}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Title" required className="sm:col-span-2"><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} disabled={!ed && !isNew} /></Field>
          <Field label="Type"><EnumSelect value={f.audit_type} onChange={(v) => setF({ ...f, audit_type: v })} values={["internal", "external", "certification", "surveillance", "supplier"]} disabled={!ed && !isNew} /></Field>
          <Field label="Lead auditor"><OwnerSelect value={f.lead_auditor_id} onChange={(v) => setF({ ...f, lead_auditor_id: v })} disabled={!ed && !isNew} /></Field>
          <Field label="Planned start"><DateInput value={f.planned_start} onChange={(v) => setF({ ...f, planned_start: v })} disabled={!ed && !isNew} /></Field>
          <Field label="Planned end"><DateInput value={f.planned_end} onChange={(v) => setF({ ...f, planned_end: v })} disabled={!ed && !isNew} /></Field>
          <Field label="Scope" className="sm:col-span-2"><Textarea value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })} disabled={!ed && !isNew} /></Field>
          <Field label="Criteria and method" className="sm:col-span-2"><Textarea value={f.criteria} onChange={(e) => setF({ ...f, criteria: e.target.value })} disabled={!ed && !isNew} /></Field>
          <Field label="Controls in scope" className="sm:col-span-2"><MultiSelect value={f.control_ids} onChange={(v) => setF({ ...f, control_ids: v })} options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} /></Field>
          {!isNew && <><Field label="Summary" className="sm:col-span-2"><Textarea value={f.summary} onChange={(e) => setF({ ...f, summary: e.target.value })} disabled={!ed} /></Field>
          <Field label="Conclusion" className="sm:col-span-2"><Textarea value={f.conclusion} onChange={(e) => setF({ ...f, conclusion: e.target.value })} disabled={!ed} /></Field></>}
        </div>
        {(ed || isNew) && <Button loading={save.isPending} onClick={() => save.mutate(undefined)}>{isNew ? "Plan audit" : "Save"}</Button>}
        {a && (
          <Section title={`Findings (${a.findings.length})`}>
            <div className="space-y-2">
              {a.findings.map((x: any) => <div key={x.id} className="rounded-lg border p-3 text-sm"><div className="flex items-center gap-2"><Badge tone={FT[x.finding_type][1]}>{FT[x.finding_type][0]}</Badge>{x.title}</div>{x.evidence && <p className="mt-1 text-xs text-muted-foreground">Evidence: {x.evidence}</p>}{x.nonconformity_id && <p className="mt-1 text-xs text-primary">Opened NC-{String(x.nonconformity_id).padStart(4, "0")}</p>}</div>)}
            </div>
            {can("audit.findings") && ["in_progress", "reporting"].includes(a.status) && (
              <div className="mt-3 space-y-2 rounded-lg border border-dashed p-3">
                <div className="grid gap-2 sm:grid-cols-[1fr_2fr]">
                  <EnumSelect value={fd.finding_type} onChange={(v) => setFd({ ...fd, finding_type: v })} values={Object.keys(FT)} labels={Object.fromEntries(Object.entries(FT).map(([k, v]) => [k, v[0]]))} />
                  <Input placeholder="Finding" value={fd.title} onChange={(e) => setFd({ ...fd, title: e.target.value })} />
                </div>
                <Input placeholder="Evidence (what was sampled or seen)" value={fd.evidence} onChange={(e) => setFd({ ...fd, evidence: e.target.value })} />
                <Select value={fd.common_control_id} onChange={(v) => setFd({ ...fd, common_control_id: v })} allowEmpty emptyLabel="No specific control" options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} />
                <p className="text-xs text-muted-foreground">Major and minor nonconformities open a nonconformity record automatically.</p>
                <Button size="sm" disabled={!fd.title} onClick={() => find.mutate(undefined)}>Record finding</Button>
              </div>
            )}
          </Section>
        )}
      </div>
    </Sheet>
  );
}

// ---- Management review ------------------------------------------------------------------------------

export function Reviews() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any[]>("/reviews");
  const [nw, setNw] = useState<any>(null);
  const create = useAction((b: any) => api("/reviews", { body: b }), { success: "Draft created with compiled inputs.", invalidate: ["/reviews"], onSuccess: (r: any) => { setNw(null); setParams({ open: String(r.id) }); } });
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ClipboardCheck} title="Management review" description="ISO 27001 9.3. Inputs are compiled from live records and frozen when the review is finalised."
        actions={can("review.write") && <Button onClick={() => setNw({ title: `Management review ${new Date().toLocaleString(undefined, { month: "long", year: "numeric" })}`, held_on: new Date().toISOString().slice(0, 10), attendees: "" })}><Plus /> Prepare review</Button>} />
      <DataTable rows={data} rowKey={(r: any) => r.id} onRowClick={(r: any) => setParams({ open: String(r.id) })} columns={[
        { key: "t", header: "Review", cell: (r: any) => <span className="font-medium">{r.title}</span> },
        { key: "h", header: "Held on", cell: (r: any) => fmtDate(r.held_on) },
        { key: "p", header: "Period from", cell: (r: any) => fmtDate(r.period_start) },
        { key: "s", header: "Status", cell: (r: any) => <Badge tone={r.status === "final" ? "good" : "neutral"}>{titleCase(r.status)}</Badge> },
      ]} />
      <Dialog open={!!nw} onOpenChange={(o) => !o && setNw(null)} title="Prepare a management review" footer={<Button loading={create.isPending} onClick={() => create.mutate(clean(nw))}>Compile inputs</Button>}>
        {nw && <div className="space-y-4">
          <Field label="Title"><Input value={nw.title} onChange={(e) => setNw({ ...nw, title: e.target.value })} /></Field>
          <Field label="Meeting date"><Input type="date" value={nw.held_on} onChange={(e) => setNw({ ...nw, held_on: e.target.value })} /></Field>
          <Field label="Attendees"><Input value={nw.attendees} onChange={(e) => setNw({ ...nw, attendees: e.target.value })} /></Field>
        </div>}
      </Dialog>
      {params.get("open") && <ReviewDrawer id={Number(params.get("open"))} onClose={() => setParams({})} />}
    </div>
  );
}

function kv(o: any): [string, any][] {
  return Object.entries(o ?? {}).map(([k, v]: any) => [titleCase(k), Array.isArray(v) ? (v.length ? v.join(", ") : "none") : v && typeof v === "object" ? Object.entries(v).map(([a, b]) => `${a}: ${b}`).join(", ") || "none" : v === null || v === undefined ? "—" : String(v)]);
}

function ReviewDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { can } = useAuth();
  const { data } = useApi<any>(`/reviews/${id}`);
  const [f, setF] = useState<any>(null);
  const [imp, setImp] = useState<any>({ title: "", owner_id: null, due_date: null });
  if (data && !f) setF({ attendees: data.attendees ?? "", interested_party_feedback: data.interested_party_feedback ?? "", improvement_opportunities: data.improvement_opportunities ?? "", discussion: data.discussion ?? "", decisions: data.decisions ?? "", actions: data.actions ?? "" });
  const inv = ["/reviews"];
  const save = useAction(() => api(`/reviews/${id}`, { method: "PATCH", body: clean(f) }), { success: "Saved.", invalidate: inv });
  const refresh = useAction(() => api(`/reviews/${id}/refresh`, { method: "POST" }), { success: "Inputs refreshed.", invalidate: inv });
  const improve = useAction(() => api(`/reviews/${id}/improvements`, { body: clean(imp) }), { success: "Improvement item created.", invalidate: ["/nonconformities"], onSuccess: () => setImp({ title: "", owner_id: null, due_date: null }) });
  const fin = useAction(async () => { await api(`/reviews/${id}`, { method: "PATCH", body: clean(f) }); return api(`/reviews/${id}/finalize`, { method: "POST" }); }, { success: "Review finalised.", invalidate: inv });
  const final = data?.status === "final";
  const ed = can("review.write") && !final;
  const i = data?.inputs;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data?.title ?? "Loading…"} subtitle={i && `Period ${fmtDate(i.period_start)} to ${fmtDate(i.period_end)} · compiled ${fmtDate(i.generated_at, true)}${final ? " · final, read-only" : ""}`}
      actions={ed && <><Button size="sm" variant="outline" onClick={() => refresh.mutate(undefined)}><RefreshCw /> Refresh inputs</Button><Button size="sm" onClick={() => fin.mutate(undefined)}><Stamp /> Finalise</Button></>}>
      {!data || !f ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <Section title="a) Actions from previous reviews"><KeyValue items={kv(i.a_previous_actions)} /></Section>
          <Section title="b) Internal and external issues"><KeyValue items={kv(i.b_issues)} /></Section>
          <Section title="c) Interested parties"><ul className="space-y-1 text-sm">{i.c_interested_parties.map((p: any) => <li key={p.name}><b>{p.name}</b> ({p.type}): {p.needs}</li>)}</ul></Section>
          <Section title="d1) Nonconformities and corrective actions"><KeyValue items={kv(i.d1_nonconformities)} /></Section>
          <Section title="d2) Monitoring and measurement"><KeyValue items={kv(i.d2_monitoring)} /></Section>
          <Section title="d3) Audit results"><KeyValue items={kv(i.d3_audits)} /></Section>
          <Section title="d4) Security objectives"><ul className="space-y-1 text-sm">{i.d4_objectives.map((o: any) => <li key={o.objective}>{o.objective}: {o.current ?? "—"} of {o.target ?? "—"} <Badge tone={o.status === "achieved" ? "good" : o.status === "at_risk" ? "warning" : o.status === "missed" ? "critical" : "neutral"}>{titleCase(o.status)}</Badge></li>)}</ul></Section>
          <Section title="f) Risk assessment and treatment"><KeyValue items={kv(i.f_risk)} /></Section>
          <Section title="Incidents and third parties"><KeyValue items={[...kv(i.incidents), ...kv(i.third_parties)]} /></Section>
          <Section title="Record">
            <div className="space-y-3">
              <Field label="Attendees"><Input value={f.attendees} onChange={(e) => setF({ ...f, attendees: e.target.value })} disabled={!ed} /></Field>
              <Field label="e) Feedback from interested parties"><Textarea value={f.interested_party_feedback} onChange={(e) => setF({ ...f, interested_party_feedback: e.target.value })} disabled={!ed} /></Field>
              <Field label="g) Opportunities for continual improvement"><Textarea value={f.improvement_opportunities} onChange={(e) => setF({ ...f, improvement_opportunities: e.target.value })} disabled={!ed} /></Field>
              <Field label="Discussion"><Textarea value={f.discussion} onChange={(e) => setF({ ...f, discussion: e.target.value })} disabled={!ed} /></Field>
              <Field label="Decisions (9.3.3)" required><Textarea value={f.decisions} onChange={(e) => setF({ ...f, decisions: e.target.value })} disabled={!ed} /></Field>
              <Field label="Actions, owners and dates"><Textarea value={f.actions} onChange={(e) => setF({ ...f, actions: e.target.value })} disabled={!ed} /></Field>
              {ed && <Button variant="outline" loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}
            </div>
          </Section>
          {ed && (
            <Section title="Track a decision as an improvement item">
              <div className="grid gap-2 sm:grid-cols-[2fr_1fr_1fr_auto] sm:items-end">
                <Field label="Item"><Input value={imp.title} onChange={(e) => setImp({ ...imp, title: e.target.value })} /></Field>
                <Field label="Owner"><OwnerSelect value={imp.owner_id} onChange={(v) => setImp({ ...imp, owner_id: v })} /></Field>
                <Field label="Due"><DateInput value={imp.due_date} onChange={(v) => setImp({ ...imp, due_date: v })} /></Field>
                <Button disabled={!imp.title} onClick={() => improve.mutate(undefined)}>Create</Button>
              </div>
            </Section>
          )}
        </div>
      )}
    </Sheet>
  );
}
