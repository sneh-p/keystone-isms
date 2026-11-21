import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { BookOpen, Calculator, CheckCircle2, Download, Gauge, Pencil, Plus, ShieldAlert } from "lucide-react";
import { api, downloadUrl } from "@/lib/api";
import { useAction, useApi, usePeople, useUnsavedGuard } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, fmtMoney, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { TicketButton, useTickets } from "@/components/TicketButton";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { KeyValue, PageHeader, Section, Skeleton, Stat } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { LevelBadge, StatusBadge } from "@/components/ui/status";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { HeatMap } from "@/components/viz/HeatMap";
import { clean, DateInput, EnumSelect, OwnerSelect, RangeInput } from "@/components/forms";
import { ImportButton } from "@/components/ImportDialog";
import { Comments } from "@/components/Comments";
import { RiskSuggestButton } from "@/components/AiAssist";

const LossCurve = lazy(() => import("@/components/viz/LossCurve"));

const CATEGORIES = ["strategic", "operational", "technology", "third_party", "compliance", "people", "physical", "privacy"];
const TREATMENTS = ["mitigate", "accept", "transfer", "avoid"];
const STATUSES = ["identified", "assessed", "treatment", "monitoring", "closed"];

export default function Risks() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const [closed, setClosed] = useState(false);
  const { data } = useApi<any>(`/risks?include_closed=${closed}`, ["/risks", closed]);
  const matrix = useApi<any>("/risk-matrix");
  const [cell, setCell] = useState<{ l: number; i: number } | null>(null);
  const open = params.get("open");
  if (!data || !matrix.data) return <Skeleton className="h-96" />;
  const att = data.attention;
  const rows = cell ? data.risks.filter((r: any) => (r.residual_likelihood ?? r.inherent_likelihood) === cell.l && (r.residual_impact ?? r.inherent_impact) === cell.i) : data.risks;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Gauge} title="Risk register" description={`Risk appetite: residual risk up to ${matrix.data.appetite_max_level}. Matrix and appetite are calibration starting points in config/risk_matrix.yaml.`}
        actions={<><a href={downloadUrl("/risks/treatment-plan.xlsx")}><Button variant="outline"><Download /> Treatment plan</Button></a>{can("risk.write") && <><ImportButton register="risks" noun="risks" invalidate={["/risks", "/dashboard"]} /><RiskLibrary onAdded={(id) => setParams({ open: String(id) })} /><RiskSuggestButton /><Button onClick={() => setParams({ open: "new" })}><Plus /> New risk</Button></>}</>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="Open risks" value={data.risks.filter((r: any) => r.status !== "closed").length} />
        <Stat label="Above appetite, untreated" value={att.above_appetite_untreated.length} tone={att.above_appetite_untreated.length ? "critical" : undefined} />
        <Stat label="Reviews overdue" value={att.review_overdue.length} tone={att.review_overdue.length ? "warning" : undefined} />
        <Stat label="Treatment actions overdue" value={att.actions_overdue.length} tone={att.actions_overdue.length ? "warning" : undefined} />
      </div>
      <div className="grid gap-6 2xl:grid-cols-[1fr_auto]">
        <div className="min-w-0">
          <DataTable
            rows={rows}
            rowKey={(r: any) => r.id}
            onRowClick={(r: any) => setParams({ open: String(r.id) })}
            search={(r: any) => `${r.ref} ${r.title} ${r.category}`}
            toolbar={
              <>
                <label className="flex items-center gap-2 text-sm text-muted-foreground"><input type="checkbox" checked={closed} onChange={(e) => setClosed(e.target.checked)} /> Include closed</label>
                {cell && <Button size="sm" variant="secondary" onClick={() => setCell(null)}>Clear heat map filter (L{cell.l} × I{cell.i})</Button>}
              </>
            }
            columns={[
              { key: "ref", header: "Ref", cell: (r: any) => <span className="font-mono text-xs">{r.ref}</span>, sort: (r: any) => r.id, className: "w-24" },
              { key: "title", header: "Risk", className: "min-w-[16rem]", cell: (r: any) => <div><div className="font-medium">{r.title}</div><div className="text-xs text-muted-foreground">{titleCase(r.category)} · {name(r.owner_id)}</div></div>, sort: (r: any) => r.title },
              { key: "inh", header: "Inherent", cell: (r: any) => <LevelBadge level={r.inherent_level} />, sort: (r: any) => (r.inherent_likelihood ?? 0) * (r.inherent_impact ?? 0) },
              { key: "res", header: "Residual", cell: (r: any) => (r.residual_level ? <LevelBadge level={r.residual_level} /> : <span className="text-muted-foreground">—</span>), sort: (r: any) => (r.residual_likelihood ?? 0) * (r.residual_impact ?? 0) },
              { key: "status", header: "Status", cell: (r: any) => <div className="flex flex-col items-start gap-1"><StatusBadge status={r.status} />{r.accepted_until && <span className="text-xs text-muted-foreground">accepted to {fmtDate(r.accepted_until)}</span>}</div>, sort: (r: any) => r.status },
              { key: "ale", header: "FAIR ALE", cell: (r: any) => (r.fair_result ? <span className="tabular-nums">{fmtMoney(r.fair_result.ale_mean)}</span> : "—"), sort: (r: any) => r.fair_result?.ale_mean ?? -1, className: "text-right" },
              { key: "review", header: "Next review", cell: (r: any) => <span className={att.review_overdue.includes(r.id) ? "font-medium text-critical" : ""}>{fmtDate(r.review_date)}</span>, sort: (r: any) => r.review_date ?? "" },
            ]}
          />
        </div>
        <Card className="h-fit max-w-xl 2xl:sticky 2xl:top-0 2xl:max-w-none">
          <CardHeader title="Heat map" description="Click a cell to filter." />
          <CardBody>
            <HeatMap grid={data.heat_map.current} levels={matrix.data.grid} title="Current risk" likelihood={matrix.data.likelihood} impact={matrix.data.impact} onCell={(l, i) => setCell({ l, i })} />
          </CardBody>
        </Card>
      </div>
      {open && <RiskDrawer id={open} matrix={matrix.data} onClose={() => setParams({})} onCreated={(id) => setParams({ open: String(id) })} />}
    </div>
  );
}

/** Start a risk from a Keystone library scenario (threat, weakness, consequence, suggested rating, treating controls). */
function RiskLibrary({ onAdded }: { onAdded: (id: number) => void }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [owner, setOwner] = useState<number | null>(null);
  const lib = useApi<any[]>(open ? "/risk-library" : null);
  const add = useAction((key: string) => api<{ id: number; ref: string }>("/risks/from-library", { body: { key, owner_id: owner } }), {
    success: (r) => `${r.ref} added; review the rating for your context.`, invalidate: ["/risks", "/dashboard"], onSuccess: (r) => { setOpen(false); onAdded(r.id); },
  });
  const shown = (lib.data ?? []).filter((x) => `${x.title} ${x.threat} ${x.category}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}><BookOpen /> Add from library</Button>
      <Dialog open={open} onOpenChange={setOpen} title="Risk library" description="Common scenarios written for Keystone. Each comes with a suggested starting rating and the controls that usually treat it; adjust both to your context." extraWide>
        <div className="mb-3 grid gap-2 sm:grid-cols-[1fr_16rem]">
          <Input aria-label="Search the library" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
          <OwnerSelect value={owner} onChange={setOwner} emptyLabel="Owner: decide later" ariaLabel="Risk owner" />
        </div>
        {!lib.data ? <Skeleton className="h-64" /> : (
          <ul className="divide-y rounded-md border">
            {shown.map((x) => (
              <li key={x.key} className="flex flex-wrap items-start gap-3 px-3 py-2.5 text-sm">
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{x.title}</div>
                  <div className="text-xs text-muted-foreground">{titleCase(x.category)} · {x.threat}</div>
                  <div className="mt-1 flex flex-wrap gap-1">{x.controls.map((c: string) => <Badge key={c} tone="outline" className="font-mono text-[10px]">{c}</Badge>)}</div>
                </div>
                <span className="text-xs text-muted-foreground">L{x.likelihood} × I{x.impact}</span>
                <Button size="sm" variant="outline" loading={add.isPending && add.variables === x.key} onClick={() => add.mutate(x.key)}><Plus /> Add</Button>
              </li>
            ))}
            {shown.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted-foreground">No scenario matches.</li>}
          </ul>
        )}
      </Dialog>
    </>
  );
}

function RiskDrawer({ id, matrix, onClose, onCreated }: { id: string; matrix: any; onClose: () => void; onCreated: (id: number) => void }) {
  const isNew = id === "new";
  const { data } = useApi<any>(isNew ? null : `/risks/${id}`);
  const { can } = useAuth();
  const [editing, setEditing] = useState(false);
  const [dirty, setDirty] = useState(false);
  const confirmDiscard = useUnsavedGuard(dirty);
  const stopEditing = () => { setEditing(false); setDirty(false); };
  return (
    <Sheet open onOpenChange={(o) => { if (!o && confirmDiscard()) onClose(); }} title={isNew ? "New risk" : data ? `${data.ref} · ${data.title}` : "Loading…"} subtitle={!isNew && data ? <span className="flex items-center gap-2"><StatusBadge status={data.status} /> <LevelBadge level={data.current_level} /></span> : undefined}
      actions={!isNew && data && can("risk.write") && !editing && <Button size="sm" variant="outline" onClick={() => setEditing(true)}><Pencil /> Edit</Button>}>
      {isNew ? <RiskForm matrix={matrix} onSaved={(r) => onCreated(r.id)} onDirty={setDirty} /> : !data ? <Skeleton className="h-64" /> : (
        <Tabs tabs={[
          { value: "details", label: "Details", content: editing
            ? <RiskForm risk={data} matrix={matrix} onDirty={setDirty} onSaved={stopEditing} onCancel={() => { if (confirmDiscard()) stopEditing(); }} />
            : <RiskView risk={data} matrix={matrix} /> },
          { value: "treat", label: `Treatment (${data.actions.length})`, content: <Treatment risk={data} /> },
          { value: "fair", label: "FAIR", content: <Fair risk={data} /> },
          { value: "discussion", label: "Discussion", content: <Comments kind="risk" id={Number(id)} /> },
        ]} />
      )}
    </Sheet>
  );
}

function LI({ label, lk, im, matrix, onL, onI, disabled }: any) {
  const L = Object.entries(matrix.likelihood).map(([k, v]) => ({ value: k, label: `${k} · ${v}` }));
  const I = Object.entries(matrix.impact).map(([k, v]) => ({ value: k, label: `${k} · ${v}` }));
  const level = lk && im ? matrix.grid[im - 1][lk - 1] : null;
  return (
    <div className="rounded-lg border p-3">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">{label} <LevelBadge level={level} /></div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Likelihood"><Select value={lk ? String(lk) : null} onChange={(v) => onL(v ? Number(v) : null)} allowEmpty options={L} disabled={disabled} /></Field>
        <Field label="Impact"><Select value={im ? String(im) : null} onChange={(v) => onI(v ? Number(v) : null)} allowEmpty options={I} disabled={disabled} /></Field>
      </div>
    </div>
  );
}

function RiskView({ risk, matrix }: { risk: any; matrix: any }) {
  const { name } = usePeople();
  const tickets = useTickets("risk", [risk.id]);
  const assets = useApi<any[]>("/assets");
  const controls = useApi<any[]>("/controls");
  const li = (l: number | null, i: number | null) => (l && i ? <span className="flex flex-wrap items-center gap-2"><LevelBadge level={matrix.grid[i - 1][l - 1]} /> likelihood {l} · {matrix.likelihood[l]}, impact {i} · {matrix.impact[i]}</span> : "Not assessed");
  const text = (v: string | null) => v || <span className="text-muted-foreground">—</span>;
  return (
    <div className="space-y-5">
      <KeyValue items={[
        ["Category", titleCase(risk.category)],
        ["Risk owner", risk.owner_id ? name(risk.owner_id) : "No owner"],
        ["Inherent risk", li(risk.inherent_likelihood, risk.inherent_impact)],
        ["Residual risk", li(risk.residual_likelihood, risk.residual_impact)],
        ["Treatment", risk.treatment_option ? titleCase(risk.treatment_option) : "Not decided"],
        ["Next review", fmtDate(risk.review_date)],
      ]} />
      <KeyValue items={[["Description", text(risk.description)], ["Threat", text(risk.threat)], ["Vulnerability", text(risk.vulnerability)], ["Consequence", text(risk.consequence)], ["Treatment rationale", text(risk.treatment_rationale)]]} />
      <div className="space-y-2 text-sm">
        <div className="font-medium">Affected assets</div>
        <div className="flex flex-wrap gap-1.5">{risk.asset_ids.length ? risk.asset_ids.map((a: number) => <Link key={a} to={`/assets?open=${a}`}><Badge tone="outline">{assets.data?.find((x) => x.id === a)?.name ?? `Asset ${a}`}</Badge></Link>) : <span className="text-muted-foreground">None linked</span>}</div>
        <div className="pt-2 font-medium">Treating controls</div>
        <div className="flex flex-wrap gap-1.5">{risk.control_ids.length ? risk.control_ids.map((c: number) => { const x = controls.data?.find((y) => y.id === c); return <Link key={c} to={`/controls?open=${c}`}><Badge tone="primary" className="font-mono">{x ? x.code : `Control ${c}`}</Badge></Link>; }) : <span className="text-muted-foreground">None linked</span>}</div>
        <div className="pt-2 font-medium">Incidents where it materialised</div>
        <div className="flex flex-wrap gap-1.5">{risk.incidents?.length ? risk.incidents.map((i: any) => <Link key={i.id} to={`/incidents?open=${i.id}`}><Badge tone="warning">{i.ref} {i.title}</Badge></Link>) : <span className="text-muted-foreground">None</span>}</div>
        <div className="pt-2 font-medium">Vendors involved</div>
        <div className="flex flex-wrap gap-1.5">{risk.vendors?.length ? risk.vendors.map((v: any) => <Link key={v.id} to={`/vendors?open=${v.id}`}><Badge tone="outline">{v.name}</Badge></Link>) : <span className="text-muted-foreground">None</span>}</div>
      </div>
      <TicketButton kind="risk" id={risk.id} tickets={tickets[risk.id]} />
    </div>
  );
}

function RiskForm({ risk, matrix, onSaved, onDirty, onCancel }: { risk?: any; matrix: any; onSaved?: (r: any) => void; onDirty?: (d: boolean) => void; onCancel?: () => void }) {
  const { can } = useAuth();
  const assets = useApi<any[]>("/assets");
  const controls = useApi<any[]>("/controls");
  const init = () => ({
    title: risk?.title ?? "", description: risk?.description ?? "", category: risk?.category ?? "operational", owner_id: risk?.owner_id ?? null,
    threat: risk?.threat ?? "", vulnerability: risk?.vulnerability ?? "", consequence: risk?.consequence ?? "",
    inherent_likelihood: risk?.inherent_likelihood ?? null, inherent_impact: risk?.inherent_impact ?? null, residual_likelihood: risk?.residual_likelihood ?? null, residual_impact: risk?.residual_impact ?? null,
    treatment_option: risk?.treatment_option ?? null, treatment_rationale: risk?.treatment_rationale ?? "", review_date: risk?.review_date ?? null,
    asset_ids: (risk?.asset_ids ?? []).map(String), control_ids: (risk?.control_ids ?? []).map(String),
  });
  const [f, setF] = useState<any>(init);
  const [formFor, setFormFor] = useState(risk?.id);
  if (formFor !== risk?.id) { setFormFor(risk?.id); setF(init()); } // reset the form when another risk opens
  const s = (k: string) => (v: any) => setF((p: any) => ({ ...p, [k]: v }));
  const save = useAction((body: any) => (risk ? api(`/risks/${risk.id}`, { method: "PATCH", body }) : api("/risks", { body })), { success: "Risk saved.", invalidate: ["/risks", "/dashboard", "/soa", "/controls"], onSuccess: onSaved });
  const editable = can("risk.write");
  const submit = () => save.mutate({ ...clean(f), asset_ids: f.asset_ids.map(Number), control_ids: f.control_ids.map(Number) });
  const dirty = JSON.stringify(f) !== JSON.stringify(init());
  useEffect(() => { onDirty?.(dirty); }, [dirty, onDirty]);
  return (
    <div className="space-y-4">
      <Field label="Title" required><Input value={f.title} onChange={(e) => s("title")(e.target.value)} disabled={!editable} /></Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Category"><EnumSelect value={f.category} onChange={s("category")} values={CATEGORIES} disabled={!editable} /></Field>
        <Field label="Risk owner"><OwnerSelect value={f.owner_id} onChange={s("owner_id")} disabled={!editable} /></Field>
      </div>
      <Field label="Description"><Textarea value={f.description} onChange={(e) => s("description")(e.target.value)} disabled={!editable} /></Field>
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="Threat"><Textarea value={f.threat} onChange={(e) => s("threat")(e.target.value)} disabled={!editable} /></Field>
        <Field label="Vulnerability"><Textarea value={f.vulnerability} onChange={(e) => s("vulnerability")(e.target.value)} disabled={!editable} /></Field>
        <Field label="Consequence"><Textarea value={f.consequence} onChange={(e) => s("consequence")(e.target.value)} disabled={!editable} /></Field>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <LI label="Inherent risk (before controls)" lk={f.inherent_likelihood} im={f.inherent_impact} matrix={matrix} onL={s("inherent_likelihood")} onI={s("inherent_impact")} disabled={!editable} />
        <LI label="Residual risk (with controls)" lk={f.residual_likelihood} im={f.residual_impact} matrix={matrix} onL={s("residual_likelihood")} onI={s("residual_impact")} disabled={!editable} />
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Treatment option"><EnumSelect value={f.treatment_option} onChange={s("treatment_option")} values={TREATMENTS} allowEmpty disabled={!editable} /></Field>
        <Field label="Next review"><DateInput value={f.review_date} onChange={s("review_date")} disabled={!editable} /></Field>
      </div>
      <Field label="Treatment rationale"><Textarea value={f.treatment_rationale} onChange={(e) => s("treatment_rationale")(e.target.value)} disabled={!editable} /></Field>
      <Field label="Affected assets"><MultiSelect value={f.asset_ids} onChange={s("asset_ids")} options={(assets.data ?? []).map((a) => ({ value: String(a.id), label: a.name }))} /></Field>
      <Field label="Treating controls"><MultiSelect value={f.control_ids} onChange={s("control_ids")} options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} /></Field>
      {editable && (
        <div className="flex gap-2">
          <Button loading={save.isPending} disabled={!!risk && !dirty} onClick={submit}>{risk ? "Save changes" : "Create risk"}</Button>
          {onCancel && <Button variant="ghost" onClick={onCancel}>Cancel</Button>}
        </div>
      )}
    </div>
  );
}

function Treatment({ risk }: { risk: any }) {
  const { can, me } = useAuth();
  const { name } = usePeople();
  const controls = useApi<any[]>("/controls");
  const [status, setStatus] = useState<string | null>(null);
  const [act, setAct] = useState<any>({ title: "", owner_id: null, due_date: null, common_control_id: null });
  const [accept, setAccept] = useState(false);
  const [acc, setAcc] = useState<any>({ justification: "", expires_on: null });
  const inv = ["/risks", "/dashboard"];
  const move = useAction((s: string) => api(`/risks/${risk.id}/status`, { body: { status: s } }), { success: "Status changed.", invalidate: inv });
  const review = useAction(() => api(`/risks/${risk.id}/review`, { method: "POST" }), { success: "Review recorded.", invalidate: inv });
  const addAct = useAction((b: any) => api(`/risks/${risk.id}/actions`, { body: b }), { success: "Action added.", invalidate: inv, onSuccess: () => setAct({ title: "", owner_id: null, due_date: null, common_control_id: null }) });
  const doneAct = useAction((a: any) => api(`/risks/${risk.id}/actions/${a.id}`, { method: "PATCH", body: { status: a.status } }), { invalidate: inv });
  const doAccept = useAction((b: any) => api(`/risks/${risk.id}/accept`, { body: b }), { success: "Risk accepted.", invalidate: inv, onSuccess: () => setAccept(false) });
  const revoke = useAction((aid: number) => api(`/risk-acceptances/${aid}/revoke`, { method: "POST" }), { success: "Acceptance revoked.", invalidate: inv });
  const editable = can("risk.write");
  const ctl = new Map((controls.data ?? []).map((c) => [c.id, c.code]));
  return (
    <div className="space-y-6">
      {editable && (
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Move to status" className="w-56"><EnumSelect value={status} onChange={setStatus} values={STATUSES.filter((s) => s !== risk.status)} /></Field>
          <Button variant="outline" disabled={!status} loading={move.isPending} onClick={() => status && move.mutate(status)}>Change status</Button>
          <Button variant="outline" loading={review.isPending} onClick={() => review.mutate(undefined)}><CheckCircle2 /> Record review</Button>
          {can("risk.accept") && <Button variant="outline" onClick={() => setAccept(true)} disabled={risk.owner_id === me?.id} title={risk.owner_id === me?.id ? "You own this risk" : undefined}><ShieldAlert /> Accept risk</Button>}
        </div>
      )}
      <Section title="Treatment actions">
        <DataTable rows={risk.actions} rowKey={(a: any) => a.id} empty="No actions yet." columns={[
          { key: "t", header: "Action", cell: (a: any) => <div>{a.title}{a.common_control_id && <Badge tone="primary" className="ml-2">{ctl.get(a.common_control_id)}</Badge>}</div> },
          { key: "o", header: "Owner", cell: (a: any) => name(a.owner_id) },
          { key: "d", header: "Due", cell: (a: any) => fmtDate(a.due_date) },
          { key: "s", header: "Status", cell: (a: any) => editable && a.status !== "done" ? <Button size="sm" variant="ghost" onClick={() => doneAct.mutate({ id: a.id, status: "done" })}>Mark done</Button> : <StatusBadge status={a.status} /> },
        ]} />
        {editable && (
          <div className="mt-3 grid gap-2 rounded-lg border p-3 sm:grid-cols-[2fr_1fr_1fr_auto] sm:items-end">
            <Field label="New action"><Input value={act.title} onChange={(e) => setAct({ ...act, title: e.target.value })} /></Field>
            <Field label="Owner"><OwnerSelect value={act.owner_id} onChange={(v) => setAct({ ...act, owner_id: v })} /></Field>
            <Field label="Due"><DateInput value={act.due_date} onChange={(v) => setAct({ ...act, due_date: v })} /></Field>
            <Button loading={addAct.isPending} onClick={() => addAct.mutate(clean(act))}>Add</Button>
          </div>
        )}
      </Section>
      <Section title="Acceptances">
        {risk.acceptances.length === 0 ? <p className="text-sm text-muted-foreground">Not accepted.</p> : (
          <ul className="space-y-2">
            {risk.acceptances.map((a: any) => (
              <li key={a.id} className="rounded-lg border p-3 text-sm">
                <div className="flex items-center justify-between"><span><LevelBadge level={a.level_at_acceptance} /> accepted by {name(a.accepted_by_id)} on {fmtDate(a.accepted_at)}</span>{a.revoked_at ? <Badge tone="outline">revoked</Badge> : <span className="text-muted-foreground">until {fmtDate(a.expires_on)}</span>}</div>
                <p className="mt-1 text-muted-foreground">{a.justification}</p>
                {!a.revoked_at && can("risk.accept") && <Button size="sm" variant="ghost" className="mt-1" onClick={() => revoke.mutate(a.id)}>Revoke</Button>}
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Dialog open={accept} onOpenChange={setAccept} title="Accept this risk" description={`Risks above appetite can be accepted for at most ${365} days. You cannot accept a risk you own.`} footer={<Button loading={doAccept.isPending} onClick={() => doAccept.mutate(clean(acc))}>Accept risk</Button>}>
        <div className="space-y-4">
          <Field label="Justification" required><Textarea value={acc.justification} onChange={(e) => setAcc({ ...acc, justification: e.target.value })} /></Field>
          <Field label="Expires on" hint="Leave empty for the maximum allowed."><DateInput value={acc.expires_on} onChange={(v) => setAcc({ ...acc, expires_on: v })} /></Field>
        </div>
      </Dialog>
    </div>
  );
}

const DEF = { tef: { min: 0.5, ml: 2, max: 6 }, tcap: { min: 0.3, ml: 0.6, max: 0.9 }, cs: { min: 0.4, ml: 0.6, max: 0.8 }, plm: { min: 10000, ml: 50000, max: 250000 }, slef: { min: 0.05, ml: 0.2, max: 0.5 }, slm: { min: 5000, ml: 25000, max: 150000 } };

function Fair({ risk }: { risk: any }) {
  const { can } = useAuth();
  const prev = risk.fair_inputs ?? {};
  const [inp, setInp] = useState<any>({ ...DEF, ...prev });
  const [secondary, setSecondary] = useState(!!prev.slef);
  const run = useAction((b: any) => api(`/risks/${risk.id}/fair`, { body: b }), { success: "Simulation complete.", invalidate: ["/risks"] });
  const res = risk.fair_result;
  const s = (k: string) => (v: any) => setInp((p: any) => ({ ...p, [k]: v }));
  const curve = useMemo(() => (res?.exceedance ?? []).map(([x, p]: [number, number]) => ({ loss: x, p: Math.round(p * 1000) / 10 })), [res]);
  const editable = can("risk.write");
  return (
    <div className="space-y-5">
      <p className="text-sm text-muted-foreground">Monte Carlo estimate of annualised loss (FAIR). Enter ranges as minimum / most likely / maximum.</p>
      {res && (
        <Card>
          <CardBody>
            <div className="grid gap-4 sm:grid-cols-4">
              <div><div className="text-xs text-muted-foreground">Expected annual loss</div><div className="text-xl font-semibold tabular-nums">{fmtMoney(res.ale_mean)}</div></div>
              <div><div className="text-xs text-muted-foreground">Median (P50)</div><div className="text-xl font-semibold tabular-nums">{fmtMoney(res.ale_p50)}</div></div>
              <div><div className="text-xs text-muted-foreground">P90</div><div className="text-xl font-semibold tabular-nums">{fmtMoney(res.ale_p90)}</div></div>
              <div><div className="text-xs text-muted-foreground">Vulnerability</div><div className="text-xl font-semibold tabular-nums">{Math.round(res.vulnerability * 100)}%</div></div>
            </div>
            <div className="mt-4 text-sm font-medium">Loss exceedance curve</div>
            <p className="text-xs text-muted-foreground">Chance that annual loss reaches at least each amount.</p>
            <div className="mt-2 h-56">
              <Suspense fallback={<Skeleton className="h-full" />}><LossCurve data={curve} /></Suspense>
            </div>
            <KeyValue items={[["Loss events / year", res.lef_mean.toFixed(2)], ["Chance of any loss in a year", `${Math.round(res.prob_any_loss * 100)}%`], ["Iterations", res.iterations.toLocaleString()], ["Run", fmtDate(risk.fair_run_at, true)]]} />
          </CardBody>
        </Card>
      )}
      <div className="space-y-4">
        <RangeInput label="Threat events per year" value={inp.tef} onChange={s("tef")} disabled={!editable} />
        <RangeInput label="Threat capability (0-1)" value={inp.tcap} onChange={s("tcap")} step={0.05} max={1} disabled={!editable} />
        <RangeInput label="Control strength (0-1)" value={inp.cs} onChange={s("cs")} step={0.05} max={1} disabled={!editable} />
        <RangeInput label="Primary loss per event" value={inp.plm} onChange={s("plm")} step={1000} disabled={!editable} />
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={secondary} onChange={(e) => setSecondary(e.target.checked)} disabled={!editable} /> Include secondary loss</label>
        {secondary && <>
          <RangeInput label="Secondary loss event probability (0-1)" value={inp.slef} onChange={s("slef")} step={0.05} max={1} disabled={!editable} />
          <RangeInput label="Secondary loss per event" value={inp.slm} onChange={s("slm")} step={1000} disabled={!editable} />
        </>}
        {editable && <Button loading={run.isPending} onClick={() => run.mutate({ inputs: { tef: inp.tef, tcap: inp.tcap, cs: inp.cs, plm: inp.plm, ...(secondary ? { slef: inp.slef, slm: inp.slm } : {}) }, iterations: 10000 })}><Calculator /> Run simulation</Button>}
      </div>
    </div>
  );
}
