import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { LifeBuoy, Plus } from "lucide-react";
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

const CRIT_TONE: Record<string, any> = { critical: "critical", high: "warning", medium: "primary", low: "outline" };
const TEST_TYPES = ["tabletop", "walkthrough", "simulation", "backup_restore", "full_interruption"];
const OUT_TONE: Record<string, any> = { passed: "good", passed_with_issues: "warning", failed: "critical" };
const AREAS = ["financial", "operational", "legal", "reputational"];
const inv = ["/continuity", "/dashboard"];

function hrs(h: number | null | undefined) {
  if (h == null) return "—";
  return h >= 48 && h % 24 === 0 ? `${h / 24} days` : `${h} h`;
}

const num = (v: any) => (v === "" || v == null ? null : Number(v));

/** Business continuity: which processes matter most, how fast they must recover, and proof the plans work. */
export default function Continuity() {
  const [params, setParams] = useSearchParams();
  return (
    <div className="animate-fade-in">
      <PageHeader icon={LifeBuoy} title="Business continuity" description="Business impact analysis with recovery objectives, the plans that cover each process, and the tests that prove them." />
      <Tabs value={params.get("tab") ?? "bia"} onValueChange={(v) => setParams({ tab: v })} tabs={[
        { value: "bia", label: "Business impact analysis", content: <Processes /> },
        { value: "plans", label: "Plans", content: <Plans /> },
        { value: "tests", label: "Tests", content: <Tests /> },
      ]} />
    </div>
  );
}

function Processes() {
  const { can } = useAuth();
  const { name } = usePeople();
  const { data } = useApi<any[]>("/continuity/processes");
  const plans = useApi<any[]>("/continuity/plans");
  const assets = useApi<any[]>("/assets");
  const vendors = useApi<any>("/vendors");
  const [edit, setEdit] = useState<any>(null);
  const save = useAction((b: any) => { const body = clean({ name: b.name, description: b.description, owner_id: b.owner_id, criticality: b.criticality, impact: b.impact, mtpd_hours: num(b.mtpd_hours), rto_hours: num(b.rto_hours), rpo_hours: num(b.rpo_hours), asset_ids: b.asset_ids, vendor_ids: b.vendor_ids, minimum_staff: num(b.minimum_staff), workarounds: b.workarounds, status: b.status, next_review_date: b.next_review_date }); return b.id ? api(`/continuity/processes/${b.id}`, { method: "PATCH", body }) : api("/continuity/processes", { body }); }, { success: "Process saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  if (!data || !plans.data) return <Skeleton className="h-64" />;
  const covered = new Set(plans.data.filter((p: any) => p.status === "active").flatMap((p: any) => p.process_ids ?? []));
  const set = (k: string, v: any) => setEdit({ ...edit, [k]: v });
  return (
    <>
      <DataTable rows={data} rowKey={(p: any) => p.id} search={(p: any) => p.name} onRowClick={can("continuity.write") ? (p: any) => setEdit({ ...p, impact: p.impact ?? {} }) : undefined}
        empty="No business processes yet. List what the organisation can't stop doing for long: sales, bookings, payroll, customer support."
        toolbar={can("continuity.write") && <Button size="sm" onClick={() => setEdit({ name: "", criticality: "medium", status: "active", impact: {}, asset_ids: [], vendor_ids: [] })}><Plus /> Add process</Button>}
        columns={[
          { key: "n", header: "Process", sort: (p: any) => p.name, cell: (p: any) => <div><div className="font-medium">{p.name}</div><div className="text-xs text-muted-foreground">{name(p.owner_id)}</div></div> },
          { key: "c", header: "Criticality", sort: (p: any) => ["critical", "high", "medium", "low"].indexOf(p.criticality), cell: (p: any) => <Badge tone={CRIT_TONE[p.criticality]}>{titleCase(p.criticality)}</Badge> },
          { key: "o", header: "RTO / RPO / MTPD", cell: (p: any) => <span className="tabular-nums">{hrs(p.rto_hours)} / {hrs(p.rpo_hours)} / {hrs(p.mtpd_hours)}</span> },
          { key: "p", header: "Plan", cell: (p: any) => covered.has(p.id) ? <Badge tone="good">Covered</Badge> : <Badge tone={["critical", "high"].includes(p.criticality) ? "critical" : "outline"}>No plan</Badge> },
          { key: "r", header: "Review", sort: (p: any) => p.next_review_date, cell: (p: any) => fmtDate(p.next_review_date) },
        ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} wide title={edit?.id ? edit.name : "New business process"} description="Recovery objectives in hours. The RTO can't exceed the maximum tolerable period of disruption."
        footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button>}>
        {edit && <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Process" required className="sm:col-span-2"><Input value={edit.name} onChange={(e) => set("name", e.target.value)} /></Field>
          <Field label="Criticality"><EnumSelect value={edit.criticality} onChange={(v) => set("criticality", v)} values={["critical", "high", "medium", "low"]} /></Field>
          <Field label="Description" className="sm:col-span-3"><Textarea value={edit.description ?? ""} onChange={(e) => set("description", e.target.value)} /></Field>
          <Field label="Max. tolerable disruption (h)"><Input type="number" min={0} value={edit.mtpd_hours ?? ""} onChange={(e) => set("mtpd_hours", e.target.value)} /></Field>
          <Field label="Recovery time objective (h)"><Input type="number" min={0} value={edit.rto_hours ?? ""} onChange={(e) => set("rto_hours", e.target.value)} /></Field>
          <Field label="Recovery point objective (h)" hint="Data loss tolerated."><Input type="number" min={0} value={edit.rpo_hours ?? ""} onChange={(e) => set("rpo_hours", e.target.value)} /></Field>
          <div className="sm:col-span-3"><p className="mb-2 text-sm font-medium">Impact of a one-day outage (1 = negligible, 5 = severe)</p>
            <div className="grid gap-3 sm:grid-cols-4">{AREAS.map((a) => <Field key={a} label={titleCase(a)}><Select value={edit.impact?.[a] ? String(edit.impact[a]) : null} onChange={(v) => { const imp = { ...(edit.impact ?? {}) }; if (v) imp[a] = Number(v); else delete imp[a]; set("impact", imp); }} allowEmpty emptyLabel="—" options={[1, 2, 3, 4, 5].map((n) => ({ value: String(n), label: String(n) }))} /></Field>)}</div>
          </div>
          <Field label="Systems it depends on"><MultiSelect value={(edit.asset_ids ?? []).map(String)} onChange={(v) => set("asset_ids", v.map(Number))} options={(assets.data ?? []).map((a: any) => ({ value: String(a.id), label: a.name }))} /></Field>
          <Field label="Suppliers it depends on"><MultiSelect value={(edit.vendor_ids ?? []).map(String)} onChange={(v) => set("vendor_ids", v.map(Number))} options={(vendors.data?.vendors ?? []).map((v: any) => ({ value: String(v.id), label: v.name }))} /></Field>
          <Field label="Minimum staff"><Input type="number" min={0} value={edit.minimum_staff ?? ""} onChange={(e) => set("minimum_staff", e.target.value)} /></Field>
          <Field label="Manual workarounds" className="sm:col-span-3"><Textarea value={edit.workarounds ?? ""} onChange={(e) => set("workarounds", e.target.value)} /></Field>
          <Field label="Owner"><OwnerSelect value={edit.owner_id} onChange={(v) => set("owner_id", v)} /></Field>
          <Field label="Next review"><DateInput value={edit.next_review_date} onChange={(v) => set("next_review_date", v)} /></Field>
          <Field label="Status"><EnumSelect value={edit.status} onChange={(v) => set("status", v)} values={["active", "retired"]} /></Field>
        </div>}
      </Dialog>
    </>
  );
}

function Plans() {
  const { can } = useAuth();
  const { name } = usePeople();
  const { data } = useApi<any[]>("/continuity/plans");
  const procs = useApi<any[]>("/continuity/processes");
  const [edit, setEdit] = useState<any>(null);
  const save = useAction((b: any) => { const body = clean({ title: b.title, process_ids: b.process_ids, owner_id: b.owner_id, strategy: b.strategy, activation: b.activation, test_interval_months: num(b.test_interval_months), status: b.status }); return b.id ? api(`/continuity/plans/${b.id}`, { method: "PATCH", body }) : api("/continuity/plans", { body }); }, { success: "Plan saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  if (!data || !procs.data) return <Skeleton className="h-64" />;
  const pname = new Map(procs.data.map((p: any) => [p.id, p.name]));
  const today = new Date().toISOString().slice(0, 10);
  return (
    <>
      <DataTable rows={data} rowKey={(p: any) => p.id} search={(p: any) => p.title} onRowClick={can("continuity.write") ? (p: any) => setEdit({ ...p }) : undefined}
        empty="No plans yet."
        toolbar={can("continuity.write") && <Button size="sm" onClick={() => setEdit({ title: "", process_ids: [], test_interval_months: 12, status: "active" })}><Plus /> Add plan</Button>}
        columns={[
          { key: "t", header: "Plan", sort: (p: any) => p.title, cell: (p: any) => <div><div className="font-medium">{p.title}</div><div className="text-xs text-muted-foreground">{(p.process_ids ?? []).map((id: number) => pname.get(id)).filter(Boolean).join(", ") || "No processes"}</div></div> },
          { key: "o", header: "Owner", cell: (p: any) => name(p.owner_id) },
          { key: "l", header: "Last tested", cell: (p: any) => p.last_tested_on ? <span>{fmtDate(p.last_tested_on)} <Badge tone={OUT_TONE[p.last_outcome]}>{titleCase(p.last_outcome)}</Badge></span> : <span className="text-muted-foreground">Never</span> },
          { key: "d", header: "Next test due", sort: (p: any) => p.test_due_on, cell: (p: any) => <span className={p.status === "active" && p.test_due_on <= today ? "font-medium text-critical" : undefined}>{fmtDate(p.test_due_on)}</span> },
        ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} wide title={edit?.id ? edit.title : "New continuity plan"} footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button>}>
        {edit && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Title" required className="sm:col-span-2"><Input value={edit.title} onChange={(e) => setEdit({ ...edit, title: e.target.value })} /></Field>
          <Field label="Processes covered" className="sm:col-span-2"><MultiSelect value={(edit.process_ids ?? []).map(String)} onChange={(v) => setEdit({ ...edit, process_ids: v.map(Number) })} options={procs.data.map((p: any) => ({ value: String(p.id), label: p.name }))} /></Field>
          <Field label="Recovery strategy" className="sm:col-span-2"><Textarea value={edit.strategy ?? ""} onChange={(e) => setEdit({ ...edit, strategy: e.target.value })} /></Field>
          <Field label="Activation (who invokes it, and when)" className="sm:col-span-2"><Textarea value={edit.activation ?? ""} onChange={(e) => setEdit({ ...edit, activation: e.target.value })} /></Field>
          <Field label="Owner"><OwnerSelect value={edit.owner_id} onChange={(v) => setEdit({ ...edit, owner_id: v })} /></Field>
          <Field label="Test every (months)"><Input type="number" min={1} max={36} value={edit.test_interval_months ?? 12} onChange={(e) => setEdit({ ...edit, test_interval_months: e.target.value })} /></Field>
          <Field label="Status"><EnumSelect value={edit.status} onChange={(v) => setEdit({ ...edit, status: v })} values={["active", "retired"]} /></Field>
        </div>}
      </Dialog>
    </>
  );
}

function Tests() {
  const { can } = useAuth();
  const { data } = useApi<any[]>("/continuity/tests");
  const plans = useApi<any[]>("/continuity/plans");
  const procs = useApi<any[]>("/continuity/processes");
  const [plan, setPlan] = useState<any>(null);
  const [done, setDone] = useState<any>(null);
  const create = useAction(() => api("/continuity/tests", { body: clean({ ...plan, plan_id: Number(plan.plan_id) }) }), { success: "Test planned.", invalidate: inv, onSuccess: () => setPlan(null) });
  const complete = useAction(() => api(`/continuity/tests/${done.id}/complete`, { body: { performed_on: done.performed_on, outcome: done.outcome, findings: done.findings || null, raise_nc: done.raise_nc,
    results: done.results.filter((r: any) => r.recovered_hours !== "" || r.data_loss_hours !== "").map((r: any) => ({ process_id: r.process_id, recovered_hours: num(r.recovered_hours), data_loss_hours: num(r.data_loss_hours) })) } }),
  { success: "Test recorded. Evidence filed on the continuity controls.", invalidate: [...inv, "/evidence", "/nonconformities"], onSuccess: () => setDone(null) });
  if (!data || !plans.data || !procs.data) return <Skeleton className="h-64" />;
  const plname = new Map(plans.data.map((p: any) => [p.id, p.title]));
  const pr = new Map(procs.data.map((p: any) => [p.id, p]));
  return (
    <>
      <DataTable rows={data} rowKey={(t: any) => t.id} search={(t: any) => t.title} empty="No tests yet. A tabletop exercise is a good first test."
        toolbar={can("continuity.write") && plans.data.length > 0 && <Button size="sm" onClick={() => setPlan({ plan_id: String(plans.data![0].id), title: "", test_type: "tabletop", planned_on: null, objectives: "", participants: "" })}><Plus /> Plan a test</Button>}
        columns={[
          { key: "t", header: "Test", cell: (t: any) => <div><div className="font-medium">{t.title}</div><div className="text-xs text-muted-foreground">{titleCase(t.test_type)} · {plname.get(t.plan_id)}</div></div> },
          { key: "d", header: "Date", sort: (t: any) => t.performed_on ?? t.planned_on, cell: (t: any) => t.performed_on ? fmtDate(t.performed_on) : t.planned_on ? `Planned ${fmtDate(t.planned_on)}` : "Not scheduled" },
          { key: "o", header: "Result", cell: (t: any) => t.outcome ? <div className="space-y-1"><Badge tone={OUT_TONE[t.outcome]}>{titleCase(t.outcome)}</Badge>
            {(t.results ?? []).map((r: any) => <div key={r.process_id} className="text-xs">{pr.get(r.process_id)?.name}: {hrs(r.recovered_hours)}{r.met_rto === false && <span className="text-critical"> (RTO missed)</span>}</div>)}
            {t.nonconformity_id && <Link to={`/nonconformities?open=${t.nonconformity_id}`} className="text-xs text-primary underline">Nonconformity raised</Link>}</div> : <Badge tone="outline">Planned</Badge> },
          { key: "x", header: "", cell: (t: any) => t.status === "planned" && can("continuity.write") && <Button size="sm" variant="outline" onClick={() => {
            const p = plans.data!.find((x: any) => x.id === t.plan_id);
            setDone({ id: t.id, title: t.title, performed_on: new Date().toISOString().slice(0, 10), outcome: "passed", findings: "", raise_nc: false, results: (p?.process_ids ?? []).map((id: number) => ({ process_id: id, recovered_hours: "", data_loss_hours: "" })) });
          }}>Record result</Button> },
        ]} />
      <Dialog open={!!plan} onOpenChange={(o) => !o && setPlan(null)} title="Plan a test" footer={<Button disabled={!plan?.title?.trim()} loading={create.isPending} onClick={() => create.mutate(undefined)}>Plan test</Button>}>
        {plan && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Plan" className="sm:col-span-2"><Select value={plan.plan_id} onChange={(v) => setPlan({ ...plan, plan_id: v })} options={plans.data.map((p: any) => ({ value: String(p.id), label: p.title }))} /></Field>
          <Field label="Title" required className="sm:col-span-2"><Input value={plan.title} onChange={(e) => setPlan({ ...plan, title: e.target.value })} /></Field>
          <Field label="Type"><EnumSelect value={plan.test_type} onChange={(v) => setPlan({ ...plan, test_type: v })} values={TEST_TYPES} /></Field>
          <Field label="Planned for"><DateInput value={plan.planned_on} onChange={(v) => setPlan({ ...plan, planned_on: v })} /></Field>
          <Field label="Objectives" className="sm:col-span-2"><Textarea value={plan.objectives} onChange={(e) => setPlan({ ...plan, objectives: e.target.value })} /></Field>
          <Field label="Participants" className="sm:col-span-2"><Input value={plan.participants} onChange={(e) => setPlan({ ...plan, participants: e.target.value })} /></Field>
        </div>}
      </Dialog>
      <Dialog open={!!done} onOpenChange={(o) => !o && setDone(null)} wide title="Record the result" description={done?.title} footer={<Button loading={complete.isPending} onClick={() => complete.mutate(undefined)}>Record result</Button>}>
        {done && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Performed on"><DateInput value={done.performed_on} onChange={(v) => setDone({ ...done, performed_on: v })} /></Field>
          <Field label="Outcome"><EnumSelect value={done.outcome} onChange={(v) => setDone({ ...done, outcome: v })} values={["passed", "passed_with_issues", "failed"]} /></Field>
          {done.results.length > 0 && <div className="space-y-2 sm:col-span-2"><p className="text-sm font-medium">Recovery achieved</p>
            {done.results.map((r: any, i: number) => {
              const p = pr.get(r.process_id);
              const upd = (k: string, v: any) => setDone({ ...done, results: done.results.map((x: any, j: number) => (j === i ? { ...x, [k]: v } : x)) });
              return <div key={r.process_id} className="grid items-end gap-2 sm:grid-cols-[1fr_9rem_9rem]">
                <div className="text-sm">{p?.name}<div className="text-xs text-muted-foreground">RTO {hrs(p?.rto_hours)}, RPO {hrs(p?.rpo_hours)}</div></div>
                <Field label="Recovered in (h)"><Input type="number" min={0} value={r.recovered_hours} onChange={(e) => upd("recovered_hours", e.target.value)} /></Field>
                <Field label="Data lost (h)"><Input type="number" min={0} value={r.data_loss_hours} onChange={(e) => upd("data_loss_hours", e.target.value)} /></Field>
              </div>;
            })}</div>}
          <Field label="Findings" className="sm:col-span-2" hint="Required unless the test passed."><Textarea value={done.findings} onChange={(e) => setDone({ ...done, findings: e.target.value })} /></Field>
          {done.outcome !== "passed" && <Switch checked={done.raise_nc} onChange={(v) => setDone({ ...done, raise_nc: v })} label="Raise a nonconformity for the issues found" />}
        </div>}
      </Dialog>
    </>
  );
}
