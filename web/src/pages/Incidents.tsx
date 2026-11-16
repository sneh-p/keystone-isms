import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle, Bell, Plus, Siren } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { cn, daysUntil, fmtDate, titleCase, tri } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Section, Skeleton, Stat } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { clean, EnumSelect, OwnerSelect, TriSelect } from "@/components/forms";

const CATS = ["phishing", "malware", "ransomware", "account_compromise", "data_breach", "unauthorised_access", "denial_of_service", "lost_or_stolen_device", "misconfiguration", "vendor_incident", "physical", "policy_violation", "other"];
const SEV = ["low", "medium", "high", "critical"];
const SEV_TONE: Record<string, any> = { low: "good", medium: "warning", high: "serious", critical: "critical" };

export default function Incidents() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any>("/incidents");
  const [report, setReport] = useState(false);
  if (!data) return <Skeleton className="h-96" />;
  const att = data.attention;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Siren} title="Incidents" description="Report early, work it through containment and recovery, and learn from it." actions={can("incident.write") && <Button onClick={() => setReport(true)}><Plus /> Report incident</Button>} />
      {att.notification_overdue.length > 0 && <div className="mb-4 flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/5 px-4 py-3 text-sm"><AlertTriangle className="size-4 text-critical" /> Regulator notification deadline passed for {att.notification_overdue.length} incident(s).</div>}
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        <Stat label="Open" value={att.open.length} />
        <Stat label="Notification pending" value={att.notification_due.length} tone={att.notification_due.length ? "warning" : undefined} />
        <Stat label="Notification overdue" value={att.notification_overdue.length} tone={att.notification_overdue.length ? "critical" : undefined} />
        <Stat label="Containment target missed" value={att.containment_overdue.length} tone={att.containment_overdue.length ? "warning" : undefined} />
      </div>
      <DataTable rows={data.incidents} rowKey={(i: any) => i.id} onRowClick={(i: any) => setParams({ open: String(i.id) })} search={(i: any) => `${i.title} ${i.category}`} columns={[
        { key: "t", header: "Incident", cell: (i: any) => <div><div className="font-medium">{i.title}</div><div className="text-xs text-muted-foreground">{titleCase(i.category)} · {name(i.owner_id)}</div></div> },
        { key: "s", header: "Severity", cell: (i: any) => <Badge tone={SEV_TONE[i.severity]}>{titleCase(i.severity)}</Badge>, sort: (i: any) => SEV.indexOf(i.severity) },
        { key: "st", header: "Status", cell: (i: any) => <StatusBadge status={i.status} label={titleCase(i.status) + (i.resolution && i.resolution !== "resolved" ? ` (${i.resolution.replace("_", " ")})` : "")} />, sort: (i: any) => i.status },
        { key: "d", header: "Detected", cell: (i: any) => fmtDate(i.detected_at, true), sort: (i: any) => i.detected_at },
        { key: "n", header: "Notify regulator by", cell: (i: any) => { if (i.regulator_notified_at) return <Badge tone="good">Notified</Badge>; if (!i.notification_deadline) return <span className="text-muted-foreground">—</span>; const d = daysUntil(i.notification_deadline); return <span className={cn(d !== null && d < 0 && "font-medium text-critical")}>{fmtDate(i.notification_deadline, true)}</span>; } },
      ]} />
      {report && <ReportDialog onClose={() => setReport(false)} onCreated={(id) => { setReport(false); setParams({ open: String(id) }); }} />}
      {params.get("open") && <IncidentDrawer id={Number(params.get("open"))} onClose={() => setParams({})} />}
    </div>
  );
}

function ReportDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (id: number) => void }) {
  const now = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const [f, setF] = useState<any>({ title: "", category: "other", severity: "medium", personal_data_involved: null, detected_at: now, description: "", reported_by: "" });
  const save = useAction((b: any) => api("/incidents", { body: b }), { success: "Incident reported.", invalidate: ["/incidents", "/dashboard"], onSuccess: (r: any) => onCreated(r.id) });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title="Report an incident" wide footer={<Button loading={save.isPending} onClick={() => save.mutate({ ...clean(f), detected_at: new Date(f.detected_at).toISOString() })}>Report</Button>}>
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="What happened" required className="sm:col-span-3"><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></Field>
        <Field label="Category"><EnumSelect value={f.category} onChange={(v) => setF({ ...f, category: v })} values={CATS} /></Field>
        <Field label="Severity"><EnumSelect value={f.severity} onChange={(v) => setF({ ...f, severity: v })} values={SEV} /></Field>
        <Field label="Personal data involved?"><TriSelect value={f.personal_data_involved} onChange={(v) => setF({ ...f, personal_data_involved: v })} /></Field>
        <Field label="Detected at" className="sm:col-span-2"><Input type="datetime-local" value={f.detected_at} onChange={(e) => setF({ ...f, detected_at: e.target.value })} /></Field>
        <Field label="Reported by"><Input value={f.reported_by} onChange={(e) => setF({ ...f, reported_by: e.target.value })} /></Field>
        <Field label="Description" className="sm:col-span-3"><Textarea value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
      </div>
    </Dialog>
  );
}

function IncidentDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { can } = useAuth();
  const { data } = useApi<any>(`/incidents/${id}`);
  const assets = useApi<any[]>("/assets");
  const vendors = useApi<any>("/vendors");
  const [note, setNote] = useState("");
  const [move, setMove] = useState<string | null>(null);
  const [res, setRes] = useState<string | null>(null);
  const [f, setF] = useState<any>(null);
  useEffect(() => { if (data) setF({ severity: data.severity, owner_id: data.owner_id, personal_data_involved: data.personal_data_involved, notification_required: data.notification_required, vendor_id: data.vendor_id, root_cause: data.root_cause ?? "", lessons_learned: data.lessons_learned ?? "", asset_ids: data.asset_ids.map(String) }); }, [data]);
  const inv = ["/incidents", "/dashboard"];
  const addNote = useAction(() => api(`/incidents/${id}/notes`, { body: { entry: note } }), { success: "Entry added.", invalidate: inv, onSuccess: () => setNote("") });
  const doMove = useAction(() => api(`/incidents/${id}/move`, { body: { status: move, resolution: res } }), { success: "Status updated.", invalidate: inv, onSuccess: () => setMove(null) });
  const notify = useAction(() => api(`/incidents/${id}/notify`, { method: "POST" }), { success: "Notification recorded.", invalidate: inv });
  const save = useAction((b: any) => api(`/incidents/${id}`, { method: "PATCH", body: b }), { success: "Saved.", invalidate: inv });
  const ed = can("incident.write");
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data?.title ?? "Loading…"} subtitle={data && <span className="flex items-center gap-2"><StatusBadge status={data.status} /><Badge tone={SEV_TONE[data.severity]}>{data.severity}</Badge>detected {fmtDate(data.detected_at, true)}</span>}>
      {!data || !f ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          {data.notification_deadline && !data.regulator_notified_at && (
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
              <span><Bell className="mr-1 inline size-4" /> Personal data involved: notify the regulator by <b>{fmtDate(data.notification_deadline, true)}</b>.</span>
              {ed && <Button size="sm" onClick={() => notify.mutate(undefined)}>Record notification</Button>}
            </div>
          )}
          {ed && data.allowed_moves.length > 0 && (
            <div className="flex flex-wrap items-end gap-2">
              <Field label="Move to" className="w-44"><EnumSelect value={move} onChange={setMove} values={data.allowed_moves} /></Field>
              {move === "closed" && <Field label="Resolution" className="w-44"><EnumSelect value={res} onChange={setRes} values={["resolved", "false_positive", "duplicate"]} allowEmpty /></Field>}
              <Button variant="outline" disabled={!move} loading={doMove.isPending} onClick={() => doMove.mutate(undefined)}>Move</Button>
            </div>
          )}
          <Section title="Timeline">
            <ol className="relative space-y-4 border-l pl-5">
              {data.events.map((e: any) => (
                <li key={e.id} className="relative">
                  <span className={cn("absolute -left-[25px] top-1 size-2.5 rounded-full ring-4 ring-card", e.kind === "status" ? "bg-primary" : e.kind === "system" ? "bg-muted-foreground" : "bg-good")} />
                  <div className="text-xs text-muted-foreground">{fmtDate(e.occurred_at, true)} · {e.author}</div>
                  <div className="text-sm">{e.entry}</div>
                </li>
              ))}
            </ol>
            {ed && <div className="mt-4 flex gap-2"><Input placeholder="Add a timeline entry (cannot be edited later)" value={note} onChange={(e) => setNote(e.target.value)} /><Button variant="outline" disabled={!note} onClick={() => addNote.mutate(undefined)}>Add</Button></div>}
          </Section>
          <Section title="Details">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Severity"><EnumSelect value={f.severity} onChange={(v) => setF({ ...f, severity: v })} values={SEV} disabled={!ed} /></Field>
              <Field label="Owner"><OwnerSelect value={f.owner_id} onChange={(v) => setF({ ...f, owner_id: v })} disabled={!ed} /></Field>
              <Field label="Personal data involved?"><TriSelect value={f.personal_data_involved} onChange={(v) => setF({ ...f, personal_data_involved: v })} disabled={!ed} /></Field>
              <Field label="Regulator notification required?"><TriSelect value={f.notification_required} onChange={(v) => setF({ ...f, notification_required: v })} disabled={!ed} /></Field>
              <Field label="Vendor involved"><Select value={f.vendor_id ? String(f.vendor_id) : null} onChange={(v) => setF({ ...f, vendor_id: v ? Number(v) : null })} allowEmpty options={(vendors.data?.vendors ?? []).map((v: any) => ({ value: String(v.id), label: v.name }))} disabled={!ed} /></Field>
              <Field label="Affected assets"><MultiSelect value={f.asset_ids} onChange={(v) => setF({ ...f, asset_ids: v })} options={(assets.data ?? []).map((a) => ({ value: String(a.id), label: a.name }))} /></Field>
            </div>
            <Field className="mt-4" label="Root cause" hint="Required before closing (ISO 27001 A.5.27)."><Textarea value={f.root_cause} onChange={(e) => setF({ ...f, root_cause: e.target.value })} disabled={!ed} /></Field>
            <Field className="mt-4" label="Lessons learned"><Textarea value={f.lessons_learned} onChange={(e) => setF({ ...f, lessons_learned: e.target.value })} disabled={!ed} /></Field>
            {ed && <Button className="mt-4" loading={save.isPending} onClick={() => save.mutate({ ...clean(f), asset_ids: f.asset_ids.map(Number) })}>Save details</Button>}
            <p className="mt-3 text-xs text-muted-foreground">Personal data: {tri(data.personal_data_involved)} · notification required: {tri(data.notification_required)}</p>
          </Section>
        </div>
      )}
    </Sheet>
  );
}
