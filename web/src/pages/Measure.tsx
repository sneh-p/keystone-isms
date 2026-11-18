import { useState } from "react";
import { Link } from "react-router";
import { Activity, BellRing, CheckCircle2, FileWarning, Gauge, KeyRound, Plus, Radar, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople, useUrlFilter } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { cn, fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, KeyValue, PageHeader, Section, Skeleton, Stat, Switch } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { Tabs } from "@/components/ui/tabs";
import { DateInput } from "@/components/forms";
import { CopyButton } from "@/components/CopyButton";
import { Sparkline } from "@/components/viz/Sparkline";

const ALERT_STATUS: Record<string, string> = { new: "New", acknowledged: "Acknowledged", incident: "Incident opened" };
const SEV_TONE: Record<string, string> = { critical: "critical", high: "critical", medium: "warning", low: "neutral", info: "outline" };

// ---- security alert inbox --------------------------------------------------------------------------------------------

/** Alerts from your security tools (EDR, SIEM, email, cloud, backup), and the sources allowed to send them. */
export function AlertInbox() {
  const { can } = useAuth();
  const [tab, setTab] = useUrlFilter("tab");
  const tabs = [
    ...(can("incident.write") ? [{ value: "inbox", label: "Inbox", content: <Inbox /> }] : []),
    ...(can("integration.manage") ? [{ value: "sources", label: "Sources", content: <Sources /> }] : []),
  ];
  return (
    <div className="animate-fade-in">
      <PageHeader icon={BellRing} title="Alert inbox" description="Alerts your security tools send to Keystone. Repeats are counted, each alert is linked to the asset and its owner by host name, and one click turns an alert into an incident." />
      <Tabs tabs={tabs} value={tab ?? tabs[0]?.value} onValueChange={(v) => setTab(v === tabs[0]?.value ? null : v)} />
    </div>
  );
}

function Inbox() {
  const { data } = useApi<any>("/alerts");
  const [open, setOpen] = useUrlFilter("open");
  if (!data) return <Skeleton className="h-96" />;
  const live = data.alerts.filter((a: any) => ["new", "acknowledged"].includes(a.status));
  const current = open ? data.alerts.find((a: any) => String(a.id) === open) : undefined;
  return (
    <div>
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="New" value={live.filter((a: any) => a.status === "new").length} tone={live.some((a: any) => a.status === "new") ? "warning" : undefined} />
        <Stat label="Critical or high, open" value={live.filter((a: any) => ["critical", "high"].includes(a.severity)).length} tone={live.some((a: any) => ["critical", "high"].includes(a.severity)) ? "critical" : undefined} />
        <Stat label="Acknowledged" value={live.filter((a: any) => a.status === "acknowledged").length} />
        <Stat label="Became incidents" value={data.alerts.filter((a: any) => a.status === "incident").length} />
      </div>
      <DataTable rows={data.alerts} rowKey={(a: any) => a.id} onRowClick={(a: any) => setOpen(String(a.id))} exportName="alerts" empty="No alerts yet. Add a source, then point your tool at it."
        search={(a: any) => `${a.ref} ${a.title} ${a.host ?? ""} ${a.account ?? ""} ${a.source ?? ""}`}
        columns={[
          { key: "t", header: "Alert", cell: (a: any) => <span><span className="font-medium">{a.title}</span><span className="block text-xs text-muted-foreground">{a.source} · {a.ref}{a.count > 1 ? ` · seen ${a.count} times` : ""}</span></span> },
          { key: "s", header: "Severity", cell: (a: any) => <Badge tone={SEV_TONE[a.severity] as any}>{a.severity}</Badge> },
          { key: "h", header: "Host or account", cell: (a: any) => <span>{a.host ?? a.account ?? "—"}{a.owner && <span className="block text-xs text-muted-foreground">Owner: {a.owner}</span>}</span> },
          { key: "l", header: "Last seen", cell: (a: any) => fmtDate(a.last_seen) },
          { key: "st", header: "Status", cell: (a: any) => <Badge tone={a.status === "new" ? "primary" : a.status === "incident" ? "warning" : "neutral"}>{a.status === "closed" ? data.close_reasons[a.close_reason] : ALERT_STATUS[a.status]}</Badge> },
        ]} />
      {current && <AlertPanel alert={current} reasons={data.close_reasons} onClose={() => setOpen(null)} />}
    </div>
  );
}

function AlertPanel({ alert: a, reasons, onClose }: { alert: any; reasons: Record<string, string>; onClose: () => void }) {
  const [closing, setClosing] = useState(false);
  const [reason, setReason] = useState<string | null>("benign");
  const [note, setNote] = useState("");
  const inv = ["/alerts", "/incidents", "/dashboard"];
  const ack = useAction(() => api(`/alerts/${a.id}/acknowledge`, { method: "POST" }), { success: "Acknowledged.", invalidate: inv });
  const incident = useAction(() => api<any>(`/alerts/${a.id}/incident`, { body: {} }), { success: (r: any) => `Incident ${r.ref} opened.`, invalidate: inv });
  const close = useAction(() => api(`/alerts/${a.id}/close`, { body: { reason, note } }), { success: "Alert closed.", invalidate: inv, onSuccess: () => setClosing(false) });
  const live = ["new", "acknowledged"].includes(a.status);
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={`${a.ref} · ${a.title}`} subtitle={`${a.source} · ${a.severity} · first seen ${fmtDate(a.first_seen)}${a.count > 1 ? `, ${a.count} times` : ""}`}>
      <div className="space-y-6">
        {live && (
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => incident.mutate(undefined)} loading={incident.isPending}><FileWarning /> Open an incident</Button>
            {a.status === "new" && <Button variant="outline" loading={ack.isPending} onClick={() => ack.mutate(undefined)}>Acknowledge</Button>}
            <Button variant="outline" onClick={() => setClosing(true)}><CheckCircle2 /> Close</Button>
          </div>
        )}
        <KeyValue items={[
          ["Category", a.category.replace(/_/g, " ")], ["Host", a.host ?? "—"], ["Account", a.account ?? "—"],
          ["Asset", a.asset_id ? <Link key="a" to={`/assets?open=${a.asset_id}`} className="text-primary underline">Open the asset</Link> : "Not matched"],
          ["Owner", a.owner ?? "—"], ["Details", <span key="d" className="whitespace-pre-wrap">{a.description ?? "—"}</span>],
          ["In the tool", a.link ? <a key="l" href={a.link} target="_blank" rel="noreferrer noopener" className="break-all text-primary underline">{a.link}</a> : "—"],
          ...(a.incident_id ? [["Incident", <Link key="i" to={`/incidents?open=${a.incident_id}`} className="text-primary underline">Open the incident</Link>] as [string, any]] : []),
          ...(a.status === "closed" ? [["Closed", `${reasons[a.close_reason]}: ${a.note}`] as [string, any]] : []),
        ]} />
      </div>
      {closing && (
        <Dialog open onOpenChange={(o) => !o && setClosing(false)} title="Close the alert" footer={<Button disabled={!reason || !note.trim()} loading={close.isPending} onClick={() => close.mutate(undefined)}>Close alert</Button>}>
          <div className="space-y-4">
            <Field label="Why" required><Select ariaLabel="Why" value={reason} onChange={setReason} options={Object.entries(reasons).map(([value, label]) => ({ value, label }))} /></Field>
            <Field label="Note" required hint="What you checked."><Textarea value={note} maxLength={4000} onChange={(e) => setNote(e.target.value)} /></Field>
          </div>
        </Dialog>
      )}
    </Sheet>
  );
}

function Sources() {
  const { data } = useApi<any>("/alert-sources");
  const [adding, setAdding] = useState<{ name: string; kind: string | null } | null>(null);
  const [token, setToken] = useState<{ name: string; token: string } | null>(null);
  const inv = ["/alert-sources"];
  const create = useAction(() => api<any>("/alert-sources", { body: adding }), { success: "Source added.", invalidate: inv, onSuccess: (r: any) => { setAdding(null); setToken({ name: r.name, token: r.token }); } });
  const rotate = useAction((id: number) => api<any>(`/alert-sources/${id}/token`, { method: "POST" }), { success: "New token made; the old one stopped working.", invalidate: inv, onSuccess: (r: any) => setToken({ name: r.name, token: r.token }) });
  const enable = useAction((s: any) => api(`/alert-sources/${s.id}/enabled`, { method: "PUT", body: { enabled: !s.enabled } }), { success: "Saved.", invalidate: inv });
  if (!data) return <Skeleton className="h-64" />;
  const url = `${window.location.origin}/api/inbound/alerts`;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-3xl text-sm text-muted-foreground">Each tool gets its own token, shown once and stored only as a hash. Tools post JSON to <code>{url}</code> with <code>Authorization: Bearer &lt;token&gt;</code>. Keystone never sends anything back to them.</p>
        <Button onClick={() => setAdding({ name: "", kind: null })}><Plus /> Add a source</Button>
      </div>
      <DataTable rows={data.sources} rowKey={(s: any) => s.id} empty="No sources yet." columns={[
        { key: "n", header: "Source", cell: (s: any) => <span><span className="font-medium">{s.name}</span><span className="block text-xs text-muted-foreground">{data.kinds[s.kind]}</span></span> },
        { key: "r", header: "Alerts received", cell: (s: any) => <span className="tabular-nums">{s.received}</span> },
        { key: "l", header: "Last alert", cell: (s: any) => (s.last_received_at ? fmtDate(s.last_received_at) : "Never") },
        { key: "e", header: "On", cell: (s: any) => <Switch checked={s.enabled} onChange={() => enable.mutate(s)} label={<span className="sr-only">{s.enabled ? `Turn off ${s.name}` : `Turn on ${s.name}`}</span>} /> },
        { key: "t", header: "", cell: (s: any) => <Button size="sm" variant="ghost" onClick={() => { if (window.confirm(`Make a new token for ${s.name}? The current one stops working at once.`)) rotate.mutate(s.id); }}><KeyRound /> New token</Button> },
      ]} />
      {adding && (
        <Dialog open onOpenChange={(o) => !o && setAdding(null)} title="Add a source" footer={<Button disabled={!adding.name.trim() || !adding.kind} loading={create.isPending} onClick={() => create.mutate(undefined)}>Add source</Button>}>
          <div className="space-y-4">
            <Field label="Name" required><Input value={adding.name} maxLength={100} onChange={(e) => setAdding((x) => x && { ...x, name: e.target.value })} placeholder="e.g. Defender for Endpoint" /></Field>
            <Field label="Kind of tool" required><Select ariaLabel="Kind of tool" value={adding.kind} onChange={(v) => setAdding((x) => x && { ...x, kind: v })} options={Object.entries(data.kinds).map(([value, label]) => ({ value, label: label as string }))} /></Field>
          </div>
        </Dialog>
      )}
      {token && (
        <Dialog open onOpenChange={(o) => !o && setToken(null)} wide title={`Token for ${token.name}`} description="Copy it now: it isn't shown again. Store it in the tool's webhook or notification settings.">
          <div className="space-y-4 text-sm">
            <div className="flex items-center gap-2"><code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1.5">{token.token}</code><CopyButton text={token.token} /></div>
            <p className="font-medium">Example</p>
            <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">{`curl -X POST ${url} \\
  -H "Authorization: Bearer ${token.token.slice(0, 9)}…" -H "Content-Type: application/json" \\
  -d '{"title": "Malware detected", "severity": "high", "category": "malware",
       "host": "LAPTOP-7", "external_id": "edr-123", "link": "https://your-edr/alerts/123"}'`}</pre>
            <p className="text-muted-foreground">Fields: title and severity (info, low, medium, high, critical) are required; category, external_id (to count repeats), host, account, description, link (https) and occurred_at are optional. Up to 64 KB per alert.</p>
          </div>
        </Dialog>
      )}
    </div>
  );
}

// ---- indicators -----------------------------------------------------------------------------------------------------

const STATE_TONE: Record<string, string> = { green: "good", amber: "warning", red: "critical" };
const STATE_LABEL: Record<string, string> = { green: "On track", amber: "Watch", red: "Act now" };

/** Security indicators: thresholds on figures Keystone measures every day, or that you enter (ISO 27001 9.1). */
export function Indicators() {
  const { can } = useAuth();
  const { people, name } = usePeople();
  const { data } = useApi<any>("/indicators");
  const [edit, setEdit] = useState<any>(null);
  const [value, setValue] = useState<any>(null);
  const inv = ["/indicators"];
  const recommended = useAction(() => api<any>("/indicators/recommended", { method: "POST" }), { success: (r: any) => `${r.added} indicators added.`, invalidate: inv });
  const save = useAction(() => {
    const body = { name: edit.name, description: edit.description || null, metric_key: edit.metric_key || null, unit: edit.unit || null, higher_is_better: !!edit.higher_is_better,
      amber: Number(edit.amber), red: Number(edit.red), owner_id: edit.owner_id ? Number(edit.owner_id) : null, active: edit.active !== false };
    return edit.id ? api(`/indicators/${edit.id}`, { method: "PUT", body }) : api("/indicators", { body });
  }, { success: "Indicator saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  const record = useAction(() => api(`/indicators/${value.id}/values`, { body: { value: Number(value.value), measured_on: value.measured_on, note: value.note || null } }),
    { success: "Value recorded.", invalidate: inv, onSuccess: () => setValue(null) });
  if (!data) return <Skeleton className="h-96" />;
  const write = can("org.write");
  const rows = data.indicators;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Gauge} title="Indicators" description="Key risk and performance indicators: figures Keystone measures every day (or that you enter), against amber and red thresholds. The owner is notified when one turns red."
        actions={write && <>
          <Button variant="outline" loading={recommended.isPending} onClick={() => recommended.mutate(undefined)}><RefreshCw /> Add recommended indicators</Button>
          <Button onClick={() => setEdit({ name: "", higher_is_better: false, amber: "", red: "", metric_key: null })}><Plus /> New indicator</Button>
        </>} />
      <div className="mb-5 grid grid-cols-3 gap-3 sm:gap-4">
        <Stat label="Act now" value={rows.filter((i: any) => i.active && i.last_state === "red").length} tone={rows.some((i: any) => i.active && i.last_state === "red") ? "critical" : undefined} />
        <Stat label="Watch" value={rows.filter((i: any) => i.active && i.last_state === "amber").length} tone={rows.some((i: any) => i.active && i.last_state === "amber") ? "warning" : undefined} />
        <Stat label="On track" value={rows.filter((i: any) => i.active && i.last_state === "green").length} tone="good" />
      </div>
      {rows.length === 0 ? <Empty icon={Activity} title="No indicators yet" action={write && <Button onClick={() => recommended.mutate(undefined)}>Add recommended indicators</Button>}>Start with the recommended set: MFA coverage, overdue vulnerabilities, leavers with access and more.</Empty> : (
        <DataTable rows={rows} rowKey={(i: any) => i.id} onRowClick={write ? (i: any) => setEdit({ ...i }) : undefined} exportName="indicators" search={(i: any) => i.name}
          columns={[
            { key: "n", header: "Indicator", cell: (i: any) => <span className={i.active ? undefined : "opacity-60"}><span className="font-medium">{i.name}</span><span className="block text-xs text-muted-foreground">{i.metric_key ? "Measured every day" : "Entered by hand"}{i.owner_id ? ` · ${name(i.owner_id)}` : ""}</span></span> },
            { key: "v", header: "Now", cell: (i: any) => (i.last_value === null ? <span className="text-muted-foreground">No value</span> : <span className="text-lg font-semibold tabular-nums">{i.last_value}{i.unit ?? ""}</span>) },
            { key: "tr", header: "Last 90 days", cell: (i: any) => <Sparkline values={i.history.map((h: any) => h.value)} days={i.history.map((h: any) => h.day)} label={`${i.name}, last 90 days`} /> },
            { key: "th", header: "Thresholds", cell: (i: any) => <span className="text-xs text-muted-foreground">{i.higher_is_better ? "≤" : "≥"} {i.amber}{i.unit ?? ""} watch · {i.higher_is_better ? "≤" : "≥"} {i.red}{i.unit ?? ""} act</span> },
            { key: "s", header: "State", cell: (i: any) => (i.last_state ? <Badge tone={STATE_TONE[i.last_state] as any}>{STATE_LABEL[i.last_state]}</Badge> : "—") },
            { key: "x", header: "", cell: (i: any) => (write && !i.metric_key ? <Button size="sm" variant="ghost" onClick={(e) => { e.stopPropagation(); setValue({ id: i.id, name: i.name, value: "", measured_on: null, note: "" }); }}>Record value</Button> : null) },
          ]} />
      )}
      {edit && (
        <Dialog open onOpenChange={(o) => !o && setEdit(null)} wide title={edit.id ? `Edit: ${edit.name}` : "New indicator"}
          footer={<Button disabled={!edit.name?.trim() || edit.amber === "" || edit.red === ""} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" required className="sm:col-span-2"><Input value={edit.name} maxLength={200} onChange={(e) => setEdit((x: any) => ({ ...x, name: e.target.value }))} /></Field>
            <Field label="Measured from" hint="A figure Keystone measures every day, or none to enter values by hand.">
              <Select ariaLabel="Measured from" value={edit.metric_key} allowEmpty emptyLabel="Entered by hand" onChange={(v) => setEdit((x: any) => ({ ...x, metric_key: v, ...(v ? { unit: data.metrics[v].unit, higher_is_better: data.metrics[v].higher_is_better } : {}) }))}
                options={Object.entries(data.metrics).map(([value, m]: any) => ({ value, label: m.label }))} />
            </Field>
            <Field label="Owner"><Select ariaLabel="Owner" value={edit.owner_id ? String(edit.owner_id) : null} allowEmpty emptyLabel="No owner (ISMS managers)" onChange={(v) => setEdit((x: any) => ({ ...x, owner_id: v }))} options={people.map((p) => ({ value: String(p.id), label: p.display_name }))} /></Field>
            <Field label="Better when the value is"><Select ariaLabel="Better when the value is" value={edit.higher_is_better ? "higher" : "lower"} onChange={(v) => setEdit((x: any) => ({ ...x, higher_is_better: v === "higher" }))} options={[{ value: "lower", label: "Lower" }, { value: "higher", label: "Higher" }]} /></Field>
            <Field label="Unit"><Input value={edit.unit ?? ""} maxLength={20} onChange={(e) => setEdit((x: any) => ({ ...x, unit: e.target.value }))} placeholder="e.g. %" /></Field>
            <Field label="Watch (amber) at" required><Input type="number" value={edit.amber} onChange={(e) => setEdit((x: any) => ({ ...x, amber: e.target.value }))} /></Field>
            <Field label="Act now (red) at" required><Input type="number" value={edit.red} onChange={(e) => setEdit((x: any) => ({ ...x, red: e.target.value }))} /></Field>
            <Field label="Description" className="sm:col-span-2"><Textarea value={edit.description ?? ""} maxLength={2000} onChange={(e) => setEdit((x: any) => ({ ...x, description: e.target.value }))} /></Field>
            {edit.id && <Switch checked={edit.active !== false} onChange={(v) => setEdit((x: any) => ({ ...x, active: v }))} label="In use" />}
          </div>
        </Dialog>
      )}
      {value && (
        <Dialog open onOpenChange={(o) => !o && setValue(null)} title={`Record: ${value.name}`} footer={<Button disabled={value.value === "" || Number.isNaN(Number(value.value))} loading={record.isPending} onClick={() => record.mutate(undefined)}>Record</Button>}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Value" required><Input type="number" value={value.value} onChange={(e) => setValue((x: any) => ({ ...x, value: e.target.value }))} /></Field>
            <Field label="Measured on"><DateInput ariaLabel="Measured on" value={value.measured_on} onChange={(v) => setValue((x: any) => ({ ...x, measured_on: v }))} /></Field>
            <Field label="Note" className="sm:col-span-2"><Input value={value.note} maxLength={500} onChange={(e) => setValue((x: any) => ({ ...x, note: e.target.value }))} /></Field>
          </div>
        </Dialog>
      )}
    </div>
  );
}

// ---- maturity -------------------------------------------------------------------------------------------------------

/**
 * Current against target tier per NIST CSF function. One measure on one scale (0 to 4), so one axis; two series, so a
 * legend and direct labels. Current is the app's accent bar; target is a neutral marker (the validated grey).
 */
function MaturityChart({ functions }: { functions: { ref: string; title: string; current: number | null; target: number | null }[] }) {
  const [hover, setHover] = useState<string | null>(null);
  const W = 640, rowH = 34, left = 170, right = 40, H = functions.length * rowH + 28;
  const x = (v: number) => left + (v / 4) * (W - left - right);
  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-4 text-xs text-muted-foreground" aria-hidden>
        <span className="flex items-center gap-1.5"><span className="h-2 w-4 rounded-sm bg-primary" /> Current</span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-0.5 bg-[#575760] dark:bg-[#a1a1aa]" /> Target</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label={functions.map((f) => `${f.title}: current ${f.current ?? "not scored"}, target ${f.target ?? "none"}`).join("; ")}>
        {[0, 1, 2, 3, 4].map((t) => <g key={t}><line x1={x(t)} x2={x(t)} y1={0} y2={H - 22} className="stroke-border" strokeWidth={1} /><text x={x(t)} y={H - 6} textAnchor="middle" className="fill-muted-foreground text-[10px]">{t}</text></g>)}
        {functions.map((f, i) => {
          const y = i * rowH + 8;
          return (
            <g key={f.ref} onPointerEnter={() => setHover(f.ref)} onPointerLeave={() => setHover(null)}>
              <rect x={0} y={y - 4} width={W} height={rowH - 2} className={hover === f.ref ? "fill-muted/60" : "fill-transparent"} />
              <text x={left - 10} y={y + 13} textAnchor="end" className="fill-foreground text-[12px]">{f.title}</text>
              {f.current !== null && <rect x={x(0)} y={y + 4} width={Math.max(2, x(f.current) - x(0))} height={14} rx={4} className="fill-primary" />}
              {f.target !== null && <line x1={x(f.target)} x2={x(f.target)} y1={y} y2={y + 22} strokeWidth={3} className="stroke-[#575760] dark:stroke-[#a1a1aa]" />}
              <text x={W - right + 6} y={y + 15} className="fill-muted-foreground text-[11px] tabular-nums">{f.current ?? "–"} / {f.target ?? "–"}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/** Maturity self-assessments against the NIST CSF 2.0 categories, current and target tier (0 to 4). */
export function Maturity() {
  const { can } = useAuth();
  const { data } = useApi<any>("/maturity");
  const [open, setOpen] = useUrlFilter("open");
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState("");
  const inv = ["/maturity"];
  const create = useAction(() => api<any>("/maturity", { body: { title } }), { success: "Assessment started.", invalidate: inv, onSuccess: (a: any) => { setCreating(false); setOpen(String(a.id)); } });
  if (!data) return <Skeleton className="h-96" />;
  const latest = data.assessments.find((a: any) => a.status === "final") ?? data.assessments[0];
  const current = open ? data.assessments.find((a: any) => String(a.id) === open) : undefined;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Radar} title="Maturity" description="How mature each area of security is, now and as a target, scored against the NIST CSF 2.0 categories from 0 (not done) to 4 (adaptive). Assess once or twice a year and compare."
        actions={can("org.write") && <Button onClick={() => { setTitle(`${new Date().getFullYear()} self-assessment`); setCreating(true); }}><Plus /> New assessment</Button>} />
      {!latest ? <Empty icon={Radar} title="No assessments yet">Start one and score each category. The first takes about an hour with the people who run security.</Empty> : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <Section title={`${latest.title} (${latest.status === "final" ? "final" : "draft"})`} level={2}><MaturityChart functions={latest.functions} /></Section>
          <Section title="Assessments" level={2}>
            <DataTable rows={data.assessments} rowKey={(a: any) => a.id} onRowClick={(a: any) => setOpen(String(a.id))} columns={[
              { key: "t", header: "Assessment", cell: (a: any) => <span><span className="font-medium">{a.title}</span><span className="block text-xs text-muted-foreground">{fmtDate(a.assessed_on)}</span></span> },
              { key: "s", header: "Status", cell: (a: any) => <Badge tone={a.status === "final" ? "good" : "primary"}>{a.status === "final" ? "Final" : "Draft"}</Badge> },
              { key: "a", header: "Average", cell: (a: any) => { const v = a.functions.filter((f: any) => f.current !== null); return v.length ? (v.reduce((n: number, f: any) => n + f.current, 0) / v.length).toFixed(1) : "—"; } },
            ]} />
          </Section>
        </div>
      )}
      {creating && (
        <Dialog open onOpenChange={(o) => !o && setCreating(false)} title="New assessment" footer={<Button disabled={!title.trim()} loading={create.isPending} onClick={() => create.mutate(undefined)}>Start</Button>}>
          <Field label="Title" required><Input value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} /></Field>
        </Dialog>
      )}
      {current && <AssessmentEditor a={current} categories={data.categories} tiers={data.tiers} onClose={() => setOpen(null)} />}
    </div>
  );
}

function AssessmentEditor({ a, categories, tiers, onClose }: { a: any; categories: any[]; tiers: Record<string, string>; onClose: () => void }) {
  const { can } = useAuth();
  const [scores, setScores] = useState<Record<string, any>>(a.scores ?? {});
  const locked = a.status === "final" || !can("org.write");
  const inv = ["/maturity"];
  const save = useAction(() => api(`/maturity/${a.id}`, { method: "PATCH", body: { scores } }), { success: "Saved.", invalidate: inv });
  const final = useAction(() => api(`/maturity/${a.id}/final`, { method: "POST" }), { success: "Assessment final.", invalidate: inv });
  const copy = useAction(() => api<any>(`/maturity/${a.id}/copy`, { body: { title: `${a.title} (next)` } }), { success: "Copied into a new draft.", invalidate: inv, onSuccess: onClose });
  const set = (ref: string, patch: any) => setScores((s) => ({ ...s, [ref]: { ...(s[ref] ?? {}), ...patch } }));
  const tierOpts = Object.entries(tiers).map(([value, label]) => ({ value, label: `${value}: ${label}` }));
  const done = Object.values(scores).filter((v: any) => v?.current !== null && v?.current !== undefined).length;
  const total = categories.reduce((n, f) => n + f.categories.length, 0);
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={a.title} subtitle={`${fmtDate(a.assessed_on)} · ${done} of ${total} categories scored`}
      actions={<>
        {!locked && <Button size="sm" loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}
        {!locked && <Button size="sm" variant="outline" disabled={done < total} loading={final.isPending} onClick={() => { if (window.confirm("Make this assessment final? It can't be changed afterwards.")) final.mutate(undefined); }}>Make final</Button>}
        {a.status === "final" && can("org.write") && <Button size="sm" variant="outline" loading={copy.isPending} onClick={() => copy.mutate(undefined)}>Start the next one from this</Button>}
      </>}>
      <div className="space-y-6">
        {categories.map((f) => (
          <Section key={f.ref} title={`${f.ref} · ${f.title}`} level={3}>
            <ul className="space-y-2">
              {f.categories.map((c: any) => (
                <li key={c.ref} className="rounded-md border p-3">
                  <p className="text-sm font-medium"><span className="font-mono text-xs text-muted-foreground">{c.ref}</span> {c.title.replace(`${c.ref} `, "")}</p>
                  <div className={cn("mt-2 grid gap-2 sm:grid-cols-2", locked && "pointer-events-none opacity-80")}>
                    <Select ariaLabel={`${c.ref} current tier`} value={scores[c.ref]?.current != null ? String(scores[c.ref].current) : null} placeholder="Current…" onChange={(v) => set(c.ref, { current: v === null ? null : Number(v) })} options={tierOpts} disabled={locked} />
                    <Select ariaLabel={`${c.ref} target tier`} value={scores[c.ref]?.target != null ? String(scores[c.ref].target) : null} placeholder="Target…" onChange={(v) => set(c.ref, { target: v === null ? null : Number(v) })} options={tierOpts} disabled={locked} />
                  </div>
                  {!locked ? <Input className="mt-2" aria-label={`${c.ref} note`} placeholder="Evidence or note (optional)" maxLength={1000} value={scores[c.ref]?.note ?? ""} onChange={(e) => set(c.ref, { note: e.target.value })} />
                    : scores[c.ref]?.note && <p className="mt-2 text-xs text-muted-foreground">{scores[c.ref].note}</p>}
                </li>
              ))}
            </ul>
          </Section>
        ))}
      </div>
    </Sheet>
  );
}
