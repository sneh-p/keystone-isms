import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { CheckCircle2, Handshake, Plus } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Section, Skeleton, Stat } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { LevelBadge, StatusBadge } from "@/components/ui/status";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { clean, DateInput, EnumSelect, OwnerSelect } from "@/components/forms";
import { ImportButton } from "@/components/ImportDialog";
import { Comments } from "@/components/Comments";

const TIER_TONE: Record<number, any> = { 1: "critical", 2: "serious", 3: "warning", 4: "neutral" };

export default function Vendors() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any>("/vendors");
  if (!data) return <Skeleton className="h-96" />;
  const a = data.attention;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Handshake} title="Vendors" description="Suppliers and service providers, tiered by the data they handle and the access they have." actions={can("vendor.write") && <><ImportButton register="vendors" noun="vendors" invalidate={["/vendors", "/dashboard"]} /><Button onClick={() => setParams({ open: "new" })}><Plus /> New vendor</Button></>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-5">
        <Stat label="Reviews overdue" value={a.review_overdue.length} tone={a.review_overdue.length ? "warning" : undefined} />
        <Stat label="Contracts ending soon" value={a.contract_ending.length} />
        <Stat label="Tier 1-2 need assessment" value={a.needs_assessment.length} tone={a.needs_assessment.length ? "critical" : undefined} />
        <Stat label="Personal data without DPA" value={a.no_dpa.length} tone={a.no_dpa.length ? "critical" : undefined} />
        <Stat label="Questionnaires overdue" value={a.questionnaire_overdue.length} />
      </div>
      <DataTable
        rows={data.vendors}
        rowKey={(v: any) => v.id}
        onRowClick={(v: any) => setParams({ open: String(v.id) })}
        search={(v: any) => `${v.name} ${v.services ?? ""} ${v.category ?? ""}`}
        columns={[
          { key: "name", header: "Vendor", cell: (v: any) => <div><div className="font-medium">{v.name}</div><div className="max-w-xs truncate text-xs text-muted-foreground">{v.services ?? v.website}</div></div>, sort: (v: any) => v.name },
          { key: "tier", header: "Tier", cell: (v: any) => <Badge tone={TIER_TONE[v.tier]}>Tier {v.tier} · {v.tier_label}</Badge>, sort: (v: any) => v.tier },
          { key: "status", header: "Status", cell: (v: any) => titleCase(v.status) },
          { key: "owner", header: "Owner", cell: (v: any) => name(v.owner_id) },
          { key: "dpa", header: "DPA", cell: (v: any) => (v.processes_personal_data ? (v.dpa_signed ? <Badge tone="good">Signed</Badge> : <Badge tone="critical">Missing</Badge>) : <span className="text-muted-foreground">n/a</span>) },
          { key: "entra", header: "Entra apps", cell: (v: any) => { const t = Object.entries(v.entra_presence); return t.length ? <div className="flex flex-wrap gap-1">{t.map(([n, l]: any) => <span key={n} title={n}><LevelBadge level={l} /></span>)}</div> : <span className="text-muted-foreground">—</span>; } },
          { key: "assess", header: "Last assessment", cell: (v: any) => fmtDate(v.last_assessment_at), sort: (v: any) => v.last_assessment_at ?? "" },
          { key: "review", header: "Next review", cell: (v: any) => <span className={a.review_overdue.includes(v.id) ? "font-medium text-critical" : ""}>{fmtDate(v.next_review_date)}</span>, sort: (v: any) => v.next_review_date ?? "" },
        ]}
      />
      {params.get("open") && <VendorDrawer id={params.get("open")!} tiers={data.tiers} onClose={() => setParams({})} onCreated={(id) => setParams({ open: String(id) })} />}
    </div>
  );
}

function VendorDrawer({ id, tiers, onClose, onCreated }: { id: string; tiers: any[]; onClose: () => void; onCreated: (id: number) => void }) {
  const isNew = id === "new";
  const { data } = useApi<any>(isNew ? null : `/vendors/${id}`);
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={isNew ? "New vendor" : data?.name ?? "Loading…"} subtitle={data ? `Tier ${data.tier} · ${data.tier_label}` : undefined}>
      {isNew ? <VendorForm tiers={tiers} onSaved={(v) => onCreated(v.id)} /> : !data ? <Skeleton className="h-64" /> : (
        <Tabs tabs={[
          { value: "d", label: "Details", content: <VendorForm vendor={data} tiers={tiers} /> },
          { value: "q", label: `Questionnaires (${data.questionnaires.length})`, content: (
            <DataTable rows={data.questionnaires} rowKey={(q: any) => q.id} empty="None sent yet." columns={[
              { key: "t", header: "Template", cell: (q: any) => <Link className="text-primary hover:underline" to={`/questionnaires?open=${q.id}`}>{q.template_name}</Link> },
              { key: "s", header: "Status", cell: (q: any) => <StatusBadge status={q.status} /> },
              { key: "sc", header: "Score", cell: (q: any) => (q.score !== null ? `${Math.round(q.score)}%` : "—") },
              { key: "due", header: "Due", cell: (q: any) => fmtDate(q.due_date) },
            ]} />
          ) },
          { value: "a", label: `Assessments (${data.assessments.length})`, content: (
            <DataTable rows={data.assessments} rowKey={(a: any) => a.id} empty="No assessments yet." columns={[
              { key: "t", header: "Assessment", cell: (a: any) => <Link className="text-primary hover:underline" to={`/assessments?open=${a.id}`}>{a.title}</Link> },
              { key: "s", header: "Status", cell: (a: any) => <StatusBadge status={a.status} /> },
              { key: "ale", header: "ALE", cell: (a: any) => (a.result ? Math.round(a.result.ale_mean).toLocaleString() : "—") },
            ]} />
          ) },
          { value: "e", label: "Entra exposure", content: (
            <Section title="Present in tenants">
              {Object.keys(data.entra_presence).length === 0 ? <p className="text-sm text-muted-foreground">No confirmed app mapping. Confirm the vendor's apps under Entra exposure → Matching.</p> : (
                <ul className="space-y-2">{Object.entries(data.entra_presence).map(([t, l]: any) => <li key={t} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">{t} <LevelBadge level={l} /></li>)}</ul>
              )}
            </Section>
          ) },
          { value: "discussion", label: "Discussion", content: <Comments kind="vendor" id={Number(id)} /> },
        ]} />
      )}
    </Sheet>
  );
}

function VendorForm({ vendor, tiers, onSaved }: { vendor?: any; tiers: any[]; onSaved?: (v: any) => void }) {
  const { can } = useAuth();
  const assets = useApi<any[]>("/assets");
  const risks = useApi<any>("/risks");
  const init = () => ({
    name: vendor?.name ?? "", website: vendor?.website ?? "", services: vendor?.services ?? "", category: vendor?.category ?? "", status: vendor?.status ?? "prospective", owner_id: vendor?.owner_id ?? null,
    data_sensitivity: vendor?.data_sensitivity ?? "none", operational_criticality: vendor?.operational_criticality ?? "low", access_level: vendor?.access_level ?? "none",
    processes_personal_data: vendor?.processes_personal_data ?? false, dpa_signed: vendor?.dpa_signed ?? false, tier_override: vendor?.tier_override ?? null, tier_override_reason: vendor?.tier_override_reason ?? "",
    contract_start: vendor?.contract_start ?? null, contract_end: vendor?.contract_end ?? null, notes: vendor?.notes ?? "",
    asset_ids: (vendor?.asset_ids ?? []).map(String), risk_ids: (vendor?.risk_ids ?? []).map(String),
  });
  const [f, setF] = useState<any>(init);
  const [formFor, setFormFor] = useState(vendor?.id);
  if (formFor !== vendor?.id) { setFormFor(vendor?.id); setF(init()); } // reset the form when another vendor opens
  const s = (k: string) => (v: any) => setF((p: any) => ({ ...p, [k]: v }));
  const save = useAction((b: any) => (vendor ? api(`/vendors/${vendor.id}`, { method: "PATCH", body: b }) : api("/vendors", { body: b })), { success: "Vendor saved.", invalidate: ["/vendors"], onSuccess: onSaved });
  const review = useAction(() => api(`/vendors/${vendor.id}/review`, { method: "POST" }), { success: "Review recorded.", invalidate: ["/vendors"] });
  const ed = can("vendor.write");
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" required><Input value={f.name} onChange={(e) => s("name")(e.target.value)} disabled={!ed} /></Field>
        <Field label="Website"><Input value={f.website} onChange={(e) => s("website")(e.target.value)} disabled={!ed} placeholder="vendor.com" /></Field>
        <Field label="Status"><EnumSelect value={f.status} onChange={s("status")} values={["prospective", "active", "offboarding", "terminated"]} disabled={!ed} /></Field>
        <Field label="Relationship owner"><OwnerSelect value={f.owner_id} onChange={s("owner_id")} disabled={!ed} /></Field>
      </div>
      <Field label="Services provided"><Textarea value={f.services} onChange={(e) => s("services")(e.target.value)} disabled={!ed} /></Field>
      <div className="rounded-lg border p-4">
        <div className="mb-3 text-sm font-medium">Tiering inputs</div>
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Most sensitive data"><EnumSelect value={f.data_sensitivity} onChange={s("data_sensitivity")} values={["none", "internal", "confidential", "restricted"]} disabled={!ed} /></Field>
          <Field label="Operational criticality"><EnumSelect value={f.operational_criticality} onChange={s("operational_criticality")} values={["low", "medium", "high"]} disabled={!ed} /></Field>
          <Field label="Access to our systems"><EnumSelect value={f.access_level} onChange={s("access_level")} values={["none", "sso", "delegated", "tenant_wide"]} labels={{ tenant_wide: "Tenant-wide", sso: "SSO only" }} disabled={!ed} /></Field>
        </div>
        <div className="mt-3 flex flex-wrap gap-6 text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" checked={f.processes_personal_data} onChange={(e) => s("processes_personal_data")(e.target.checked)} disabled={!ed} /> Processes personal data</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={f.dpa_signed} onChange={(e) => s("dpa_signed")(e.target.checked)} disabled={!ed} /> DPA signed</label>
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Field label="Tier override"><Select value={f.tier_override ? String(f.tier_override) : null} onChange={(v) => s("tier_override")(v ? Number(v) : null)} allowEmpty emptyLabel="Computed tier" options={tiers.map((t: any) => ({ value: String(t.tier), label: `Tier ${t.tier} · ${t.label}` }))} disabled={!ed} /></Field>
          {f.tier_override && <Field label="Override reason" required><Input value={f.tier_override_reason} onChange={(e) => s("tier_override_reason")(e.target.value)} disabled={!ed} /></Field>}
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Contract start"><DateInput value={f.contract_start} onChange={s("contract_start")} disabled={!ed} /></Field>
        <Field label="Contract end"><DateInput value={f.contract_end} onChange={s("contract_end")} disabled={!ed} /></Field>
      </div>
      <Field label="Assets they support or hold"><MultiSelect value={f.asset_ids} onChange={s("asset_ids")} options={(assets.data ?? []).map((a) => ({ value: String(a.id), label: a.name }))} /></Field>
      <Field label="Related risks"><MultiSelect value={f.risk_ids} onChange={s("risk_ids")} options={(risks.data?.risks ?? []).map((r: any) => ({ value: String(r.id), label: `${r.ref} ${r.title}` }))} /></Field>
      <Field label="Notes"><Textarea value={f.notes} onChange={(e) => s("notes")(e.target.value)} disabled={!ed} /></Field>
      {ed && (
        <div className="flex gap-2">
          <Button loading={save.isPending} onClick={() => save.mutate({ ...clean(f), asset_ids: f.asset_ids.map(Number), risk_ids: f.risk_ids.map(Number) })}>{vendor ? "Save changes" : "Create vendor"}</Button>
          {vendor && <Button variant="outline" loading={review.isPending} onClick={() => review.mutate(undefined)}><CheckCircle2 /> Record review</Button>}
        </div>
      )}
    </div>
  );
}
