import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { AlertTriangle, Fingerprint, Plus } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Skeleton, Switch } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { clean, DateInput, EnumSelect, OwnerSelect } from "@/components/forms";

const BASES = ["consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"];
const SAFEGUARDS: Record<string, string> = { none: "None (no transfers)", adequacy: "Adequacy decision", scc: "Standard contractual clauses", bcr: "Binding corporate rules", derogation: "Article 49 derogation" };
const REQ_TYPES = ["access", "rectification", "erasure", "restriction", "portability", "objection", "automated_decision"];
const OUTCOMES: Record<string, string> = { proceed: "Proceed", proceed_with_measures: "Proceed with measures", consult_authority: "Consult the authority first", do_not_proceed: "Don't proceed" };
const STATUS_TONE: Record<string, any> = { draft: "outline", in_review: "warning", approved: "good", rejected: "critical", new: "outline", verifying: "warning", in_progress: "primary", completed: "good", refused: "neutral" };
const LEVEL = ["", "Low", "Medium", "High"];
const inv = ["/privacy", "/dashboard"];

/** Privacy: records of processing, DPIAs, data subject requests and the breach log. */
export default function Privacy() {
  const [params, setParams] = useSearchParams();
  const { can } = useAuth();
  const tab = params.get("tab") ?? "ropa";
  const tabs = [
    { value: "ropa", label: "Records of processing", content: <Activities /> },
    { value: "dpias", label: "DPIAs", content: <Dpias /> },
    ...(can("privacy.write") ? [{ value: "requests", label: "Data subject requests", content: <Requests /> }] : []),
    { value: "breaches", label: "Breach log", content: <Breaches /> },
  ];
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Fingerprint} title="Privacy" description="What personal data you process and why, the impact assessments, people's requests, and every personal data breach." />
      <Tabs value={tab} onValueChange={(v) => setParams({ tab: v })} tabs={tabs} />
    </div>
  );
}

function Activities() {
  const { can } = useAuth();
  const { name } = usePeople();
  const { data } = useApi<any[]>("/privacy/activities");
  const vendors = useApi<any>("/vendors");
  const assets = useApi<any[]>("/assets");
  const [edit, setEdit] = useState<any>(null);
  const save = useAction((b: any) => { const body = clean({ ...b }); delete body.id; delete body.updated_at; return b.id ? api(`/privacy/activities/${b.id}`, { method: "PATCH", body }) : api("/privacy/activities", { body }); }, { success: "Record saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  if (!data) return <Skeleton className="h-64" />;
  const vname = new Map((vendors.data?.vendors ?? []).map((v: any) => [v.id, v.name]));
  const set = (k: string, v: any) => setEdit({ ...edit, [k]: v });
  return (
    <>
      <DataTable rows={data} rowKey={(a: any) => a.id} search={(a: any) => `${a.name} ${a.purpose}`} onRowClick={can("privacy.write") ? (a: any) => setEdit({ ...a }) : undefined}
        empty="No processing records yet. Start with your main activities: customers, staff, marketing, suppliers."
        toolbar={can("privacy.write") && <Button size="sm" onClick={() => setEdit({ name: "", purpose: "", role: "controller", lawful_basis: "contract", transfer_safeguard: "none", status: "active", special_category: false, vendor_ids: [], asset_ids: [] })}><Plus /> Add record</Button>}
        columns={[
          { key: "n", header: "Activity", sort: (a: any) => a.name, cell: (a: any) => <div><div className="font-medium">{a.name}{a.status === "retired" && <Badge tone="outline" className="ml-2">Retired</Badge>}</div><div className="line-clamp-2 text-xs text-muted-foreground">{a.purpose}</div></div> },
          { key: "b", header: "Lawful basis", cell: (a: any) => <span>{titleCase(a.lawful_basis)}{a.special_category && <Badge tone="warning" className="ml-1">Special category</Badge>}</span> },
          { key: "p", header: "Processors", cell: (a: any) => <span className="text-xs">{(a.vendor_ids ?? []).map((id: number) => vname.get(id) ?? `#${id}`).join(", ") || "None"}</span> },
          { key: "t", header: "Transfers", cell: (a: any) => a.transfers ? <span className="text-xs">{a.transfers} · {SAFEGUARDS[a.transfer_safeguard]}</span> : <span className="text-xs text-muted-foreground">None</span> },
          { key: "o", header: "Owner", cell: (a: any) => name(a.owner_id) },
          { key: "r", header: "Review", sort: (a: any) => a.next_review_date, cell: (a: any) => fmtDate(a.next_review_date) },
        ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} wide title={edit?.id ? edit.name : "New processing record"} description="Article 30 record of processing activities."
        footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button>}>
        {edit && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Activity" required><Input value={edit.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. Guest bookings" /></Field>
          <Field label="Our role"><EnumSelect value={edit.role} onChange={(v) => set("role", v)} values={["controller", "processor", "joint_controller"]} /></Field>
          <Field label="Purpose" required className="sm:col-span-2"><Textarea value={edit.purpose} onChange={(e) => set("purpose", e.target.value)} /></Field>
          <Field label="Lawful basis"><EnumSelect value={edit.lawful_basis} onChange={(v) => set("lawful_basis", v)} values={BASES} /></Field>
          {edit.lawful_basis === "legitimate_interests" ? <Field label="Legitimate interest pursued" required><Input value={edit.legitimate_interest ?? ""} onChange={(e) => set("legitimate_interest", e.target.value)} /></Field> : <div />}
          <Switch checked={!!edit.special_category} onChange={(v) => set("special_category", v)} label="Includes special category data (health, biometrics, beliefs...)" />
          {edit.special_category ? <Field label="Article 9 condition" required><Input value={edit.special_condition ?? ""} onChange={(e) => set("special_condition", e.target.value)} placeholder="e.g. 9(2)(b) employment law" /></Field> : <div />}
          <Field label="People"><Input value={edit.data_subjects ?? ""} onChange={(e) => set("data_subjects", e.target.value)} placeholder="Guests, staff, website visitors" /></Field>
          <Field label="Data"><Input value={edit.data_categories ?? ""} onChange={(e) => set("data_categories", e.target.value)} placeholder="Names, contact details, payment references" /></Field>
          <Field label="Recipients"><Input value={edit.recipients ?? ""} onChange={(e) => set("recipients", e.target.value)} /></Field>
          <Field label="Retention"><Input value={edit.retention ?? ""} onChange={(e) => set("retention", e.target.value)} placeholder="e.g. 7 years after stay (tax law)" /></Field>
          <Field label="Processors (suppliers)"><MultiSelect value={(edit.vendor_ids ?? []).map(String)} onChange={(v) => set("vendor_ids", v.map(Number))} options={(vendors.data?.vendors ?? []).map((v: any) => ({ value: String(v.id), label: v.name }))} /></Field>
          <Field label="Systems (assets)"><MultiSelect value={(edit.asset_ids ?? []).map(String)} onChange={(v) => set("asset_ids", v.map(Number))} options={(assets.data ?? []).map((a: any) => ({ value: String(a.id), label: a.name }))} /></Field>
          <Field label="Transfers outside the EEA" hint="Countries, or leave empty."><Input value={edit.transfers ?? ""} onChange={(e) => set("transfers", e.target.value)} /></Field>
          <Field label="Transfer safeguard"><EnumSelect value={edit.transfer_safeguard} onChange={(v) => set("transfer_safeguard", v)} values={Object.keys(SAFEGUARDS)} labels={SAFEGUARDS} /></Field>
          <Field label="Security measures" className="sm:col-span-2"><Textarea value={edit.security_measures ?? ""} onChange={(e) => set("security_measures", e.target.value)} /></Field>
          <Field label="DPIA needed?"><Select value={edit.dpia_required == null ? null : String(edit.dpia_required)} onChange={(v) => set("dpia_required", v == null ? null : v === "true")} allowEmpty emptyLabel="Not assessed" options={[{ value: "true", label: "Yes" }, { value: "false", label: "No" }]} /></Field>
          <Field label="Owner"><OwnerSelect value={edit.owner_id} onChange={(v) => set("owner_id", v)} /></Field>
          <Field label="Next review"><DateInput value={edit.next_review_date} onChange={(v) => set("next_review_date", v)} /></Field>
          <Field label="Status"><EnumSelect value={edit.status} onChange={(v) => set("status", v)} values={["active", "retired"]} /></Field>
        </div>}
      </Dialog>
    </>
  );
}

function Dpias() {
  const { can, me: user } = useAuth();
  const { name } = usePeople();
  const { data } = useApi<any[]>("/privacy/dpias");
  const acts = useApi<any[]>("/privacy/activities");
  const [edit, setEdit] = useState<any>(null);
  const [decide, setDecide] = useState<any>(null);
  const save = useAction((b: any) => { const body = clean({ title: b.title, activity_id: b.activity_id, description: b.description, necessity: b.necessity, risks: b.risks, dpo_advice: b.dpo_advice, outcome: b.outcome, next_review_date: b.next_review_date }); return b.id ? api(`/privacy/dpias/${b.id}`, { method: "PATCH", body }) : api("/privacy/dpias", { body }); }, { success: "DPIA saved.", invalidate: inv, onSuccess: (r: any) => setEdit({ ...r }) });
  const submit = useAction((id: number) => api(`/privacy/dpias/${id}/submit`, { method: "POST" }), { success: "Submitted for a decision.", invalidate: inv, onSuccess: () => setEdit(null) });
  const doDecide = useAction(() => api(`/privacy/dpias/${decide.id}/decide`, { body: { approve: decide.approve, note: decide.note } }), { success: "Decision recorded.", invalidate: inv, onSuccess: () => setDecide(null) });
  if (!data || !acts.data) return <Skeleton className="h-64" />;
  const aname = new Map(acts.data.map((a: any) => [a.id, a.name]));
  const set = (k: string, v: any) => setEdit({ ...edit, [k]: v });
  const locked = edit && ["approved", "rejected"].includes(edit.status);
  return (
    <>
      <DataTable rows={data} rowKey={(d: any) => d.id} search={(d: any) => d.title} onRowClick={(d: any) => setEdit({ ...d, risks: d.risks ?? [] })}
        empty="No DPIAs yet. Assess high-risk processing (large-scale special category data, monitoring, new technology) before it starts."
        toolbar={can("privacy.write") && <Button size="sm" onClick={() => setEdit({ title: "", risks: [], status: "draft" })}><Plus /> New DPIA</Button>}
        columns={[
          { key: "t", header: "DPIA", sort: (d: any) => d.title, cell: (d: any) => <div><div className="font-medium">{d.title}</div><div className="text-xs text-muted-foreground">{d.activity_id ? aname.get(d.activity_id) : "No processing record linked"}</div></div> },
          { key: "s", header: "Status", cell: (d: any) => <span className="flex flex-wrap gap-1"><Badge tone={STATUS_TONE[d.status]}>{titleCase(d.status)}</Badge>{d.high_residual && <Badge tone="critical"><AlertTriangle className="h-3 w-3" />High residual risk</Badge>}</span> },
          { key: "o", header: "Outcome", cell: (d: any) => d.outcome ? OUTCOMES[d.outcome] : "—" },
          { key: "d", header: "Decided", cell: (d: any) => d.decided_at ? `${fmtDate(d.decided_at)} by ${name(d.decided_by_id)}` : "—" },
          { key: "x", header: "", cell: (d: any) => d.status === "in_review" && can("risk.accept") && user?.id !== d.submitted_by_id && user?.id !== d.created_by_id
            ? <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); setDecide({ id: d.id, title: d.title, approve: true, note: "" }); }}>Decide</Button> : null },
        ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} wide title={edit?.id ? edit.title : "New DPIA"} description={edit?.status === "in_review" ? "Submitted: changing it sends it back to draft." : locked ? `Decided: ${edit.decision_note}` : "Article 35 data protection impact assessment."}
        footer={!locked && can("privacy.write") && <>
          {edit?.id && edit.status === "draft" && <Button variant="outline" loading={submit.isPending} onClick={() => submit.mutate(edit.id)}>Submit for decision</Button>}
          <Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button></>}>
        {edit && <fieldset disabled={locked || !can("privacy.write")} className="grid gap-4 sm:grid-cols-2">
          <Field label="Title" required><Input value={edit.title} onChange={(e) => set("title", e.target.value)} /></Field>
          <Field label="Processing record"><Select value={edit.activity_id ? String(edit.activity_id) : null} onChange={(v) => set("activity_id", v ? Number(v) : null)} allowEmpty emptyLabel="None" options={acts.data.map((a: any) => ({ value: String(a.id), label: a.name }))} /></Field>
          <Field label="The processing" className="sm:col-span-2"><Textarea value={edit.description ?? ""} onChange={(e) => set("description", e.target.value)} placeholder="What, how, scope, context and purposes" /></Field>
          <Field label="Necessity and proportionality" className="sm:col-span-2"><Textarea value={edit.necessity ?? ""} onChange={(e) => set("necessity", e.target.value)} /></Field>
          <div className="space-y-2 sm:col-span-2">
            <p className="text-sm font-medium">Risks to people</p>
            {(edit.risks ?? []).map((r: any, i: number) => {
              const upd = (k: string, v: any) => set("risks", edit.risks.map((x: any, j: number) => (j === i ? { ...x, [k]: v } : x)));
              const lvl = (k: string) => <Select ariaLabel={k} value={r[k] ? String(r[k]) : null} onChange={(v) => upd(k, v ? Number(v) : null)} allowEmpty emptyLabel="—" options={[1, 2, 3].map((n) => ({ value: String(n), label: LEVEL[n] }))} />;
              return <div key={i} className="grid gap-2 rounded-md border p-2 sm:grid-cols-[2fr_5rem_5rem_2fr_5rem_auto]">
                <Input aria-label="Risk" value={r.risk} onChange={(e) => upd("risk", e.target.value)} placeholder="Risk to people" />{lvl("likelihood")}{lvl("severity")}
                <Input aria-label="Measures" value={r.measures ?? ""} onChange={(e) => upd("measures", e.target.value)} placeholder="Measures" />{lvl("residual")}
                <Button size="sm" variant="ghost" onClick={() => set("risks", edit.risks.filter((_: any, j: number) => j !== i))}>Remove</Button>
              </div>;
            })}
            <Button size="sm" variant="outline" onClick={() => set("risks", [...(edit.risks ?? []), { risk: "", likelihood: null, severity: null, measures: "", residual: null }])}><Plus /> Add risk</Button>
            <p className="text-xs text-muted-foreground">Columns: risk, likelihood, severity, measures, residual risk. A high residual risk means the authority must be consulted before processing starts.</p>
          </div>
          <Field label="DPO's advice" className="sm:col-span-2"><Textarea value={edit.dpo_advice ?? ""} onChange={(e) => set("dpo_advice", e.target.value)} /></Field>
          <Field label="Proposed outcome"><EnumSelect value={edit.outcome} onChange={(v) => set("outcome", v)} values={Object.keys(OUTCOMES)} labels={OUTCOMES} allowEmpty /></Field>
          <Field label="Review by"><DateInput value={edit.next_review_date} onChange={(v) => set("next_review_date", v)} /></Field>
        </fieldset>}
      </Dialog>
      <Dialog open={!!decide} onOpenChange={(o) => !o && setDecide(null)} title="Decide DPIA" description={decide?.title} footer={<Button disabled={!decide?.note?.trim()} loading={doDecide.isPending} onClick={() => doDecide.mutate(undefined)}>Record decision</Button>}>
        {decide && <div className="space-y-3">
          <Select value={decide.approve ? "yes" : "no"} onChange={(v) => setDecide({ ...decide, approve: v === "yes" })} ariaLabel="Decision" options={[{ value: "yes", label: "Approve: the residual risk is acceptable" }, { value: "no", label: "Reject: rework or don't proceed" }]} />
          <Field label="Reason" required><Textarea value={decide.note} onChange={(e) => setDecide({ ...decide, note: e.target.value })} /></Field>
        </div>}
      </Dialog>
    </>
  );
}

function Requests() {
  const { name } = usePeople();
  const { data } = useApi<any[]>("/privacy/requests");
  const [edit, setEdit] = useState<any>(null);
  const [close, setClose] = useState<any>(null);
  const save = useAction((b: any) => { const body = clean({ request_type: b.request_type, received_on: b.received_on, channel: b.channel, requester_name: b.requester_name, requester_contact: b.requester_contact, details: b.details, identity_verified: b.identity_verified, assignee_id: b.assignee_id }); return b.id ? api(`/privacy/requests/${b.id}`, { method: "PATCH", body }) : api("/privacy/requests", { body }); }, { success: "Request saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  const move = useAction((v: any) => api(`/privacy/requests/${v.id}/status`, { body: { status: v.status, outcome: v.outcome ?? null } }), { success: "Status updated.", invalidate: inv, onSuccess: () => setClose(null) });
  const extend = useAction((v: any) => api(`/privacy/requests/${v.id}/extend`, { body: { reason: v.reason } }), { success: "Deadline extended by two months.", invalidate: inv });
  if (!data) return <Skeleton className="h-64" />;
  const today = new Date().toISOString().slice(0, 10);
  const open = (r: any) => !["completed", "refused"].includes(r.status);
  return (
    <>
      <p className="mb-3 text-sm text-muted-foreground">Visible only to people who handle privacy. Answer within one month; one extension of two more months is allowed with a reason. Names and contact details are removed a year after a request is closed.</p>
      <DataTable rows={data} rowKey={(r: any) => r.id} onRowClick={(r: any) => open(r) && setEdit({ ...r })}
        empty="No requests recorded."
        toolbar={<Button size="sm" onClick={() => setEdit({ request_type: "access", received_on: today, identity_verified: false })}><Plus /> Log a request</Button>}
        columns={[
          { key: "t", header: "Request", cell: (r: any) => <div><div className="font-medium">{titleCase(r.request_type)}</div><div className="text-xs text-muted-foreground">{r.redacted_at ? "Details removed" : r.requester_name ?? "Name not recorded"} · received {fmtDate(r.received_on)}</div></div> },
          { key: "s", header: "Status", cell: (r: any) => <span className="flex flex-wrap gap-1"><Badge tone={STATUS_TONE[r.status]}>{titleCase(r.status)}</Badge>{!r.identity_verified && open(r) && <Badge tone="warning">Identity not verified</Badge>}</span> },
          { key: "d", header: "Due", sort: (r: any) => r.due_date, cell: (r: any) => <span className={open(r) && r.due_date < today ? "font-medium text-critical" : undefined}>{fmtDate(r.due_date)}{r.extended && <span className="text-xs text-muted-foreground"> (extended)</span>}</span> },
          { key: "a", header: "Handled by", cell: (r: any) => name(r.assignee_id) },
          { key: "x", header: "", cell: (r: any) => open(r) ? <span className="flex flex-wrap gap-1" onClick={(e) => e.stopPropagation()}>
            {r.status === "new" && <Button size="sm" variant="ghost" onClick={() => move.mutate({ id: r.id, status: r.identity_verified ? "in_progress" : "verifying" })}>Start</Button>}
            {!r.extended && <Button size="sm" variant="ghost" onClick={() => { const reason = prompt("Why does this request need more time? (complex or numerous requests)"); if (reason) extend.mutate({ id: r.id, reason }); }}>Extend</Button>}
            <Button size="sm" variant="outline" onClick={() => setClose({ id: r.id, status: "completed", outcome: "" })}>Close</Button>
          </span> : <span className="text-xs text-muted-foreground">{fmtDate(r.closed_on)}</span> },
        ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title={edit?.id ? `Request ${titleCase(edit.request_type)}` : "Log a data subject request"} footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button>}>
        {edit && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Type"><EnumSelect value={edit.request_type} onChange={(v) => setEdit({ ...edit, request_type: v })} values={REQ_TYPES} /></Field>
          <Field label="Received on"><DateInput value={edit.received_on} onChange={(v) => setEdit({ ...edit, received_on: v })} /></Field>
          <Field label="Requester"><Input value={edit.requester_name ?? ""} onChange={(e) => setEdit({ ...edit, requester_name: e.target.value })} autoComplete="off" /></Field>
          <Field label="Contact"><Input value={edit.requester_contact ?? ""} onChange={(e) => setEdit({ ...edit, requester_contact: e.target.value })} autoComplete="off" /></Field>
          <Field label="Channel"><Input value={edit.channel ?? ""} onChange={(e) => setEdit({ ...edit, channel: e.target.value })} placeholder="Email, web form, letter" /></Field>
          <Field label="Handled by"><OwnerSelect value={edit.assignee_id} onChange={(v) => setEdit({ ...edit, assignee_id: v })} /></Field>
          <Field label="What was asked" className="sm:col-span-2"><Textarea value={edit.details ?? ""} onChange={(e) => setEdit({ ...edit, details: e.target.value })} /></Field>
          <Switch checked={!!edit.identity_verified} onChange={(v) => setEdit({ ...edit, identity_verified: v })} label="Identity verified" />
        </div>}
      </Dialog>
      <Dialog open={!!close} onOpenChange={(o) => !o && setClose(null)} title="Close the request" footer={<Button disabled={!close?.outcome?.trim()} loading={move.isPending} onClick={() => move.mutate(close)}>Close request</Button>}>
        {close && <div className="space-y-3">
          <Select value={close.status} onChange={(v) => setClose({ ...close, status: v })} ariaLabel="Result" options={[{ value: "completed", label: "Completed" }, { value: "refused", label: "Refused (with reason)" }]} />
          <Field label={close.status === "refused" ? "Why it was refused" : "What was done"} required><Textarea value={close.outcome} onChange={(e) => setClose({ ...close, outcome: e.target.value })} /></Field>
        </div>}
      </Dialog>
    </>
  );
}

function Breaches() {
  const { can } = useAuth();
  const { data } = useApi<any[]>("/privacy/breaches");
  const [edit, setEdit] = useState<any>(null);
  const save = useAction((b: any) => api(`/privacy/breaches/${b.incident_id}`, { method: "PUT", body: clean({ data_categories: b.data_categories, subjects_affected: b.subjects_affected === "" || b.subjects_affected == null ? null : Number(b.subjects_affected), records_affected: b.records_affected === "" || b.records_affected == null ? null : Number(b.records_affected), consequences: b.consequences, measures: b.measures, risk_level: b.risk_level, rationale: b.rationale, authority_reference: b.authority_reference }) }), { success: "Assessment saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  if (!data) return <Skeleton className="h-64" />;
  return (
    <>
      <p className="mb-3 text-sm text-muted-foreground">Every incident involving personal data, notified or not (GDPR Article 33(5)). Notification deadlines and dates come from the incident; record the assessment here.</p>
      <DataTable rows={data} rowKey={(b: any) => b.incident_id} empty="No incidents involving personal data."
        columns={[
          { key: "i", header: "Incident", cell: (b: any) => <div><Link to={`/incidents?open=${b.incident_id}`} className="font-medium hover:underline">{b.ref} {b.title}</Link><div className="text-xs text-muted-foreground">Detected {fmtDate(b.detected_at, true)}</div></div> },
          { key: "r", header: "Risk to people", cell: (b: any) => b.assessment?.risk_level ? <Badge tone={b.assessment.risk_level === "high_risk" ? "critical" : b.assessment.risk_level === "risk" ? "warning" : "outline"}>{titleCase(b.assessment.risk_level)}</Badge> : <Badge tone="warning">Not assessed</Badge> },
          { key: "n", header: "Authority", cell: (b: any) => b.notification_required === false ? "Not required" : b.regulator_notified_at ? `Notified ${fmtDate(b.regulator_notified_at, true)}` : b.deadline ? <span className={b.late ? "font-medium text-critical" : undefined}>Due {fmtDate(b.deadline, true)}{b.late ? " (late)" : ""}</span> : "Not decided" },
          { key: "s", header: "People told", cell: (b: any) => b.assessment?.subjects_notified_at ? fmtDate(b.assessment.subjects_notified_at) : "—" },
          { key: "x", header: "", cell: (b: any) => can("privacy.write") && <Button size="sm" variant="outline" onClick={() => setEdit({ incident_id: b.incident_id, title: `${b.ref} ${b.title}`, ...(b.assessment ?? {}) })}>{b.assessment ? "Edit" : "Assess"}</Button> },
        ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} wide title="Breach assessment" description={edit?.title} footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button>}>
        {edit && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Data involved" className="sm:col-span-2"><Input value={edit.data_categories ?? ""} onChange={(e) => setEdit({ ...edit, data_categories: e.target.value })} /></Field>
          <Field label="People affected (approx.)"><Input type="number" min={0} value={edit.subjects_affected ?? ""} onChange={(e) => setEdit({ ...edit, subjects_affected: e.target.value })} /></Field>
          <Field label="Records affected (approx.)"><Input type="number" min={0} value={edit.records_affected ?? ""} onChange={(e) => setEdit({ ...edit, records_affected: e.target.value })} /></Field>
          <Field label="Likely consequences" className="sm:col-span-2"><Textarea value={edit.consequences ?? ""} onChange={(e) => setEdit({ ...edit, consequences: e.target.value })} /></Field>
          <Field label="Measures taken or proposed" className="sm:col-span-2"><Textarea value={edit.measures ?? ""} onChange={(e) => setEdit({ ...edit, measures: e.target.value })} /></Field>
          <Field label="Risk to people"><EnumSelect value={edit.risk_level} onChange={(v) => setEdit({ ...edit, risk_level: v })} values={["no_risk", "risk", "high_risk"]} allowEmpty /></Field>
          <Field label="Authority reference"><Input value={edit.authority_reference ?? ""} onChange={(e) => setEdit({ ...edit, authority_reference: e.target.value })} /></Field>
          <Field label="Why the authority and people were, or weren't, told" className="sm:col-span-2"><Textarea value={edit.rationale ?? ""} onChange={(e) => setEdit({ ...edit, rationale: e.target.value })} /></Field>
        </div>}
      </Dialog>
    </>
  );
}
