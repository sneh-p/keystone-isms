import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { Calculator, Check, Plus, Scale, Send, Sparkles, X } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, fmtMoney, fmtNum } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Section, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { LevelBadge, StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { RangeInput } from "@/components/forms";

const LABEL: Record<string, string> = { integration_depth: "Integration depth", plm: "Primary loss magnitude", slm: "Secondary loss magnitude", control_strength: "Control strength", tef: "Threat event frequency" };
const fmtR = (v: any) => (v === null || v === undefined ? "—" : typeof v === "object" ? `${fmtNum(v.min)} / ${fmtNum(v.ml)} / ${fmtNum(v.max)}` : String(v));

export default function Assessments() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any[]>("/assessments");
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Scale} title="Vendor risk assessments" description="FAIR-based assessment of a loss scenario involving a vendor. Values are calibration starting points; review them before relying on them."
        actions={can("vendor.write") && <Button onClick={() => setParams({ open: "new" })}><Plus /> New assessment</Button>} />
      <DataTable rows={data} rowKey={(a: any) => a.id} onRowClick={(a: any) => setParams({ open: String(a.id) })} search={(a: any) => `${a.vendor_name} ${a.title}`} columns={[
        { key: "v", header: "Vendor", cell: (a: any) => <span className="font-medium">{a.vendor_name}</span>, sort: (a: any) => a.vendor_name },
        { key: "t", header: "Assessment", cell: (a: any) => a.title },
        { key: "s", header: "Status", cell: (a: any) => <StatusBadge status={a.status} />, sort: (a: any) => a.status },
        { key: "d", header: "Integration depth", cell: (a: any) => a.integration_depth ?? "—" },
        { key: "ale", header: "Expected annual loss", cell: (a: any) => (a.result ? <span className="tabular-nums">{fmtMoney(a.result.ale_mean)}</span> : "—"), sort: (a: any) => a.result?.ale_mean ?? -1, className: "text-right" },
        { key: "ap", header: "Approved", cell: (a: any) => (a.approved_at ? `${fmtDate(a.approved_at)} · ${name(a.approved_by_id)}` : "—") },
      ]} />
      {params.get("open") && <AssessmentDrawer id={params.get("open")!} onClose={() => setParams({})} onCreated={(id) => setParams({ open: String(id) })} />}
    </div>
  );
}

const DEF = { tef: { min: 0.1, ml: 0.5, max: 2 }, tcap: { min: 0.4, ml: 0.6, max: 0.9 }, control_strength: { min: 0.4, ml: 0.6, max: 0.8 }, plm: { min: 20000, ml: 100000, max: 500000 }, slef: { min: 0.05, ml: 0.2, max: 0.5 }, slm: { min: 10000, ml: 50000, max: 300000 } };

function AssessmentDrawer({ id, onClose, onCreated }: { id: string; onClose: () => void; onCreated: (id: number) => void }) {
  const { can, me } = useAuth();
  const isNew = id === "new";
  const { data } = useApi<any>(isNew ? null : `/assessments/${id}`);
  const vendors = useApi<any>("/vendors");
  const tenants = useApi<any[]>("/exposure/tenants");
  const [f, setF] = useState<any>({ vendor_id: null, title: "", scenario: "", integration_depth: "", entra_tenant_id: null, ...DEF });
  const [concl, setConcl] = useState("");
  useEffect(() => {
    if (data) setF({ vendor_id: String(data.vendor_id), title: data.title, scenario: data.scenario ?? "", integration_depth: data.integration_depth ?? "", entra_tenant_id: data.entra_tenant_id ? String(data.entra_tenant_id) : null, tef: data.tef ?? DEF.tef, tcap: data.tcap ?? DEF.tcap, control_strength: data.control_strength ?? DEF.control_strength, plm: data.plm ?? DEF.plm, slef: data.slef ?? DEF.slef, slm: data.slm ?? DEF.slm });
  }, [data]);
  const inv = ["/assessments", "/vendors"];
  const body = () => ({ title: f.title, scenario: f.scenario || null, integration_depth: f.integration_depth || null, entra_tenant_id: f.entra_tenant_id ? Number(f.entra_tenant_id) : null, tef: f.tef, tcap: f.tcap, control_strength: f.control_strength, plm: f.plm, slef: f.slef, slm: f.slm });
  const save = useAction(() => (isNew ? api("/assessments", { body: { vendor_id: Number(f.vendor_id), ...body() } }) : api(`/assessments/${id}`, { method: "PATCH", body: body() })), { success: "Assessment saved.", invalidate: inv, onSuccess: (r: any) => isNew && onCreated(r.id) });
  const act = (path: string, b?: any) => (b ? api(`/assessments/${id}/${path}`, { body: b }) : api(`/assessments/${id}/${path}`, { method: "POST" }));
  const run = useAction(() => act("run"), { success: "Simulation complete.", invalidate: inv });
  const submit = useAction(() => act("submit"), { success: "Submitted for approval.", invalidate: inv });
  const approve = useAction(() => act("approve", { conclusion: concl }), { success: "Assessment approved.", invalidate: inv });
  const ret = useAction(() => act("return"), { success: "Returned to draft.", invalidate: inv });
  const gen = useAction(() => api(`/exposure/assessments/${id}/suggestions`, { method: "POST" }), { success: "Suggestions generated.", invalidate: ["/assessments"] });
  const dec = useAction((v: { sid: number; ok: boolean }) => api(`/exposure/suggestions/${v.sid}/${v.ok ? "accept" : "reject"}`, { method: "POST" }), { invalidate: ["/assessments"] });
  const all = useAction(() => api(`/exposure/assessments/${id}/suggestions/accept-all`, { method: "POST" }), { success: "All suggestions accepted.", invalidate: ["/assessments"] });
  const draft = isNew || data?.status === "draft";
  const ed = can("vendor.write") && draft;
  const s = (k: string) => (v: any) => setF((p: any) => ({ ...p, [k]: v }));
  const pending = (data?.suggestions ?? []).filter((x: any) => x.status === "pending");
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={isNew ? "New vendor assessment" : data ? `${data.vendor_name} · ${data.title}` : "Loading…"} subtitle={data && <StatusBadge status={data.status} />}
      actions={!isNew && data && <>
        {ed && <Button size="sm" variant="outline" loading={run.isPending} onClick={() => run.mutate(undefined)}><Calculator /> Run FAIR</Button>}
        {ed && <Button size="sm" loading={submit.isPending} onClick={() => submit.mutate(undefined)}><Send /> Submit</Button>}
      </>}>
      {!isNew && !data ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          {data?.result && (
            <Card><CardBody className="grid gap-4 sm:grid-cols-4">
              <div><div className="text-xs text-muted-foreground">Expected annual loss</div><div className="text-xl font-semibold tabular-nums">{fmtMoney(data.result.ale_mean)}</div></div>
              <div><div className="text-xs text-muted-foreground">P50</div><div className="text-xl font-semibold tabular-nums">{fmtMoney(data.result.ale_p50)}</div></div>
              <div><div className="text-xs text-muted-foreground">P90</div><div className="text-xl font-semibold tabular-nums">{fmtMoney(data.result.ale_p90)}</div></div>
              <div><div className="text-xs text-muted-foreground">Vulnerability</div><div className="text-xl font-semibold tabular-nums">{Math.round(data.result.vulnerability * 100)}%</div></div>
            </CardBody></Card>
          )}
          {!isNew && (
            <Section title="Entra exposure" action={ed && f.entra_tenant_id && <Button size="sm" variant="outline" loading={gen.isPending} onClick={() => gen.mutate(undefined)}><Sparkles /> Suggest FAIR inputs</Button>}>
              {data.exposure ? <p className="mb-3 text-sm">Apps: {data.exposure.apps.join(", ")} · worst <LevelBadge level={data.exposure.worst_level} /> · {data.exposure.integration_depth}</p> : <p className="mb-3 text-sm text-muted-foreground">Scope the assessment to an Entra tenant (below) and confirm the vendor's apps under Entra exposure → Matching to get suggestions.</p>}
              {data.suggestions.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs text-muted-foreground">Suggestions never change the assessment until accepted. Ranges are calibration starting points.</p>
                  {data.suggestions.map((sg: any) => (
                    <div key={sg.id} className="rounded-lg border p-3 text-sm">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div><span className="font-medium">{LABEL[sg.field] ?? sg.field}</span>: <span className="text-muted-foreground">{fmtR(sg.current_value)}</span> → <span className="font-semibold">{fmtR(sg.suggested_value)}</span></div>
                        {sg.status === "pending" && ed ? (
                          <div className="flex gap-1"><Button size="sm" variant="outline" onClick={() => dec.mutate({ sid: sg.id, ok: true })}><Check /> Accept</Button><Button size="sm" variant="ghost" onClick={() => dec.mutate({ sid: sg.id, ok: false })}><X /> Reject</Button></div>
                        ) : <Badge tone={sg.status === "accepted" ? "good" : sg.status === "rejected" ? "outline" : "primary"}>{sg.status}{sg.decided_by ? ` by ${sg.decided_by}` : ""}</Badge>}
                      </div>
                      <ul className="mt-2 space-y-1 text-xs text-muted-foreground">{sg.reasons.map((r: any, i: number) => <li key={i}><code className="mr-1 rounded bg-muted px-1">{r.rule_id}</code>{r.text}</li>)}</ul>
                    </div>
                  ))}
                  {pending.length > 1 && ed && <Button size="sm" variant="secondary" onClick={() => all.mutate(undefined)}>Accept all pending</Button>}
                </div>
              )}
            </Section>
          )}
          <div className="space-y-4">
            {isNew && <Field label="Vendor" required><Select value={f.vendor_id} onChange={s("vendor_id")} options={(vendors.data?.vendors ?? []).map((v: any) => ({ value: String(v.id), label: v.name }))} /></Field>}
            <Field label="Title" required><Input value={f.title} onChange={(e) => s("title")(e.target.value)} disabled={!ed} /></Field>
            <Field label="Loss scenario"><Textarea value={f.scenario} onChange={(e) => s("scenario")(e.target.value)} disabled={!ed} /></Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Integration depth"><Input value={f.integration_depth} onChange={(e) => s("integration_depth")(e.target.value)} disabled={!ed} /></Field>
              <Field label="Entra tenant scope"><Select value={f.entra_tenant_id} onChange={s("entra_tenant_id")} allowEmpty emptyLabel="Not scoped" options={(tenants.data ?? []).map((t) => ({ value: String(t.id), label: t.name }))} disabled={!ed} /></Field>
            </div>
            <RangeInput label="Threat event frequency / year" value={f.tef} onChange={s("tef")} disabled={!ed} />
            <RangeInput label="Threat capability (0-1)" value={f.tcap} onChange={s("tcap")} step={0.05} max={1} disabled={!ed} />
            <RangeInput label="Control strength (0-1)" value={f.control_strength} onChange={s("control_strength")} step={0.05} max={1} disabled={!ed} />
            <RangeInput label="Primary loss magnitude" value={f.plm} onChange={s("plm")} step={1000} disabled={!ed} />
            <RangeInput label="Secondary loss event probability (0-1)" value={f.slef} onChange={s("slef")} step={0.05} max={1} disabled={!ed} />
            <RangeInput label="Secondary loss magnitude" value={f.slm} onChange={s("slm")} step={1000} disabled={!ed} />
            {ed && <Button loading={save.isPending} onClick={() => save.mutate(undefined)}>{isNew ? "Create assessment" : "Save"}</Button>}
          </div>
          {data?.status === "in_review" && can("vendor.approve") && (
            <Section title="Approval">
              {data.created_by_id === me?.id && <p className="mb-2 text-sm text-muted-foreground">You wrote this assessment, so someone else must approve it.</p>}
              <Textarea placeholder="Conclusion" value={concl} onChange={(e) => setConcl(e.target.value)} />
              <div className="mt-2 flex gap-2"><Button loading={approve.isPending} onClick={() => approve.mutate(undefined)}>Approve</Button><Button variant="ghost" onClick={() => ret.mutate(undefined)}>Return to draft</Button></div>
            </Section>
          )}
          {data?.conclusion && <p className="rounded-md bg-muted p-3 text-sm"><span className="font-medium">Conclusion:</span> {data.conclusion}</p>}
        </div>
      )}
    </Sheet>
  );
}
