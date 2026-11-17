import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { AlertTriangle, Download, KeyRound, Plus, RotateCcw, ServerCog, ShieldOff, Trash2, Upload } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, KeyValue, PageHeader, Progress, Section, Skeleton, Stat, Switch } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { DateInput } from "@/components/forms";
import { CopyButton } from "@/components/CopyButton";
import { describeExpected, expectedFromInput, expectedToInput, resultLabel, type Setting } from "@/lib/configcheck";

const SEV_TONE: Record<string, Tone> = { critical: "critical", high: "serious", medium: "warning", low: "outline" };
const RESULT_TONE: Record<string, Tone> = { pass: "good", fail: "critical", unknown: "warning", na: "outline", excepted: "neutral" };
const STATE: Record<string, [string, Tone]> = {
  compliant: ["Compliant", "good"], failing: ["Failing", "critical"], unknown: ["Incomplete", "warning"], waiting: ["Waiting for a report", "outline"],
  no_baseline: ["No baseline", "outline"], revoked: ["Revoked", "neutral"],
};
const INV = ["/config", "/dashboard", "/controls", "/evidence"];

function Sev({ s }: { s: string }) {
  return <Badge tone={SEV_TONE[s] ?? "outline"}>{titleCase(s)}</Badge>;
}

function Result({ s }: { s: string }) {
  return <Badge tone={RESULT_TONE[s] ?? "outline"}>{resultLabel(s)}</Badge>;
}

function StateBadge({ t }: { t: any }) {
  const [label, tone] = STATE[t.state] ?? [t.state, "outline"];
  return <span className="inline-flex flex-wrap gap-1"><Badge tone={tone}>{label}</Badge>{t.stale && t.state !== "revoked" && t.state !== "waiting" && <Badge tone="warning">Out of date</Badge>}</span>;
}

function Value({ v }: { v: any }) {
  if (v === null || v === undefined) return <span className="text-muted-foreground">Not reported</span>;
  if (v === true) return <>On</>;
  if (v === false) return <>Off</>;
  if (Array.isArray(v)) return <>{v.join(", ") || "None"}</>;
  return <>{String(v)}</>;
}

/** Configuration baselines: what each platform's settings must be, and which hosts and firewalls meet them. */
export default function Configuration() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? (params.get("target") ? "targets" : "overview");
  const { data } = useApi<any>("/config/overview");
  const { data: catalogue } = useApi<any>("/config/catalogue");
  const { can } = useAuth();
  if (!data || !catalogue) return <Skeleton className="h-96" />;
  const go = (v: string) => setParams({ tab: v });
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ServerCog} title="Configuration" description="Set the required settings for Windows and Linux hosts and for firewalls. Agents on the hosts report their settings (they never change anything); firewall configurations are uploaded. Anything not reported counts as unknown, never as passing." />
      <Tabs value={tab} onValueChange={go} tabs={[
        { value: "overview", label: "Overview", content: <Overview data={data} catalogue={catalogue} go={go} /> },
        { value: "targets", label: "Hosts and firewalls", content: <Targets catalogue={catalogue} /> },
        { value: "baselines", label: "Baselines", content: <Baselines catalogue={catalogue} /> },
        ...(can("integration.manage") ? [
          { value: "agents", label: "Agents", content: <Agents /> },
          { value: "upload", label: "Upload firewall configuration", content: <UploadFirewall catalogue={catalogue} /> },
        ] : []),
      ]} />
    </div>
  );
}

function Overview({ data, catalogue, go }: { data: any; catalogue: any; go: (t: string) => void }) {
  const { can } = useAuth();
  const total = Object.values(data.platforms).reduce((n: number, p: any) => n + p.targets, 0);
  const sum = (k: string) => Object.values(data.platforms).reduce((n: number, p: any) => n + p[k], 0);
  if (!total) {
    return (
      <Empty icon={ServerCog} title="Nothing checked yet"
        action={can("integration.manage") && <div className="flex flex-wrap justify-center gap-2"><Button onClick={() => go("agents")}>Install an agent</Button><Button variant="outline" onClick={() => go("upload")}>Upload a firewall configuration</Button></div>}>
        Create a baseline for each platform (the recommended settings are filled in for you), then install the report-only agent on Windows and Linux hosts, or upload configuration exports from FortiGate, PAN-OS, Cisco and pfSense/OPNsense firewalls.
      </Empty>
    );
  }
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="Hosts and firewalls" value={total} to="/configuration?tab=targets" />
        <Stat label="Compliant" value={sum("compliant")} tone={sum("compliant") === total ? "good" : undefined} hint="Every rule passes or has an exception" />
        <Stat label="Failing" value={sum("failing")} tone={sum("failing") ? "critical" : "good"} hint={`${sum("fail_results")} failing result(s)`} to="/configuration?tab=targets" />
        <Stat label="Out of date" value={sum("stale")} tone={sum("stale") ? "warning" : undefined} hint={`No agent report in ${data.report_hours * 3} hours, or a firewall upload older than 90 days`} />
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="By platform" description="Targets that meet their baseline." />
          <CardBody className="space-y-4">
            {catalogue.platforms.filter((p: any) => data.platforms[p.key].targets).map((p: any) => {
              const s = data.platforms[p.key];
              const pct = Math.round((100 * s.compliant) / s.targets);
              return (
                <div key={p.key}>
                  <div className="mb-1 flex justify-between text-sm"><span>{p.label}</span><span className="text-muted-foreground">{s.compliant} of {s.targets} compliant{s.stale ? ` · ${s.stale} out of date` : ""}</span></div>
                  <Progress label={`${p.label} compliance`} value={pct} tone={pct === 100 ? "good" : "primary"} />
                </div>
              );
            })}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Most common failures" description="Settings failing on the most targets, most severe first." />
          <CardBody className="p-0">
            {data.top_failures.length === 0 ? <p className="p-5 text-sm text-muted-foreground">No failing settings.</p> : (
              <ul className="divide-y">
                {data.top_failures.map((f: any) => (
                  <li key={`${f.platform}-${f.key}`} className="flex items-center justify-between gap-3 px-5 py-2.5 text-sm">
                    <span className="min-w-0"><span className="mr-2"><Sev s={f.severity} /></span>{f.title}<span className="block text-xs text-muted-foreground">{catalogue.platforms.find((p: any) => p.key === f.platform)?.label}</span></span>
                    <span className="shrink-0 tabular-nums">{f.targets} target(s)</span>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- targets

function Targets({ catalogue }: { catalogue: any }) {
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any[]>("/config/targets");
  const [platform, setPlatform] = useState<string | null>(null);
  const label = (k: string) => catalogue.platforms.find((p: any) => p.key === k)?.label ?? k;
  const open = params.get("target");
  const rows = (data ?? []).filter((t) => !platform || t.platform === platform);
  return (
    <>
      <DataTable rows={rows} rowKey={(t: any) => t.id} onRowClick={(t: any) => setParams({ tab: "targets", target: String(t.id) })} rowLabel={(t: any) => t.name}
        search={(t: any) => `${t.name} ${t.hostname ?? ""} ${t.os_name ?? ""}`} empty="No hosts or firewalls yet."
        toolbar={<Select ariaLabel="Platform" value={platform} onChange={setPlatform} allowEmpty emptyLabel="All platforms" options={catalogue.platforms.map((p: any) => ({ value: p.key, label: p.label }))} className="w-48" />}
        columns={[
          { key: "n", header: "Name", mobile: "heading", cell: (t: any) => <span><span className="font-medium">{t.name}</span>{t.hostname && t.hostname !== t.name && <span className="block text-xs text-muted-foreground">{t.hostname}</span>}</span>, sort: (t: any) => t.name },
          { key: "p", header: "Platform", cell: (t: any) => <span>{label(t.platform)}<span className="block text-xs text-muted-foreground">{t.kind === "agent" ? "Agent" : "Uploaded configuration"}</span></span>, sort: (t: any) => t.platform },
          { key: "b", header: "Baseline", cell: (t: any) => t.baseline ?? <span className="text-muted-foreground">None</span> },
          { key: "s", header: "Status", cell: (t: any) => <StateBadge t={t} />, sort: (t: any) => t.state },
          { key: "c", header: "Results", cell: (t: any) => <span className="tabular-nums text-xs">{t.counts.fail} failing · {t.counts.unknown} unknown · {t.counts.pass} passing</span>, sort: (t: any) => -t.counts.fail },
          { key: "r", header: "Last report", cell: (t: any) => (t.facts_at ? fmtDate(t.facts_at, true) : "—"), sort: (t: any) => t.facts_at ?? "" },
        ]} />
      {open && <TargetDrawer id={Number(open)} onClose={() => setParams({ tab: "targets" })} catalogue={catalogue} />}
    </>
  );
}

function TargetDrawer({ id, onClose, catalogue }: { id: number; onClose: () => void; catalogue: any }) {
  const { data: t } = useApi<any>(`/config/targets/${id}`);
  const { data: baselines } = useApi<any[]>("/config/baselines");
  const { can } = useAuth();
  const [except, setExcept] = useState<any>(null);
  const assign = useAction((v: any) => api(`/config/targets/${id}`, { method: "PATCH", body: v }), { success: "Saved.", invalidate: INV });
  const revoke = useAction(() => api(`/config/targets/${id}/revoke`, { method: "POST" }), { success: "Agent token revoked.", invalidate: INV });
  const remove = useAction(() => api(`/config/targets/${id}`, { method: "DELETE" }), { success: "Removed.", invalidate: INV, onSuccess: onClose });
  const unexcept = useAction((fid: number) => api(`/config/findings/${fid}/exception/revoke`, { method: "POST" }), { success: "Exception withdrawn.", invalidate: INV });
  const label = catalogue.platforms.find((p: any) => p.key === t?.platform)?.label;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={t?.name ?? "…"} subtitle={t && `${label} · ${t.kind === "agent" ? "agent" : "uploaded configuration"}`}
      actions={t && can("integration.manage") && <>
        {t.kind === "agent" && !t.revoked_at && <Button size="sm" variant="outline" loading={revoke.isPending} onClick={() => window.confirm(`Revoke ${t.name}'s agent token? It will stop reporting.`) && revoke.mutate(undefined)}><ShieldOff /> Revoke</Button>}
        <Button size="sm" variant="outline" loading={remove.isPending} onClick={() => window.confirm(`Remove ${t.name} and its results?`) && remove.mutate(undefined)}><Trash2 /> Remove</Button>
      </>}>
      {!t ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2"><StateBadge t={t} />{t.score !== null && <span className="text-sm text-muted-foreground">{t.score}% of known results pass</span>}</div>
          <KeyValue items={[
            ["Host name", t.hostname ?? "—"],
            ["Operating system", [t.os_name, t.os_version].filter(Boolean).join(" ") || "—"],
            ...(t.kind === "agent" ? [["Agent", `${t.agent_version ?? "?"} · enrolled ${fmtDate(t.enrolled_at, true)}${t.last_ip ? ` from ${t.last_ip}` : ""}`] as [string, string]] : []),
            ...(t.kind === "firewall" ? [["File", <span key="f">{t.source_filename}<span className="block break-all font-mono text-xs text-muted-foreground">SHA-256 {t.source_sha256}</span></span>] as [string, any]] : []),
            ["Last report", t.facts_at ? fmtDate(t.facts_at, true) : "Not yet"],
            ["Baseline", can("integration.manage") ? (
              <Select key="b" ariaLabel="Baseline" value={t.baseline_id && baselines?.some((b) => b.id === t.baseline_id && !b.is_default) ? String(t.baseline_id) : null} allowEmpty emptyLabel="Platform default"
                onChange={(v) => assign.mutate(v ? { baseline_id: Number(v) } : { clear_baseline: true })}
                options={(baselines ?? []).filter((b) => b.platform === t.platform).map((b) => ({ value: String(b.id), label: b.name + (b.is_default ? " (default)" : "") }))} />
            ) : t.baseline ?? "None"],
          ]} />
          {t.revoked_at && <p className="text-sm text-muted-foreground">The agent token was revoked on {fmtDate(t.revoked_at, true)}. These are its last results.</p>}
          <Section title="Results">
            {t.results.length === 0 ? <p className="text-sm text-muted-foreground">{t.baseline ? "Waiting for the first report." : "No baseline applies. Create one for this platform or assign one above."}</p> : (
              <ul className="divide-y rounded-lg border">
                {t.results.map((r: any) => (
                  <li key={r.id} className="space-y-1 px-4 py-3 text-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium">{r.title}</span>
                      <span className="flex items-center gap-1.5"><Sev s={r.severity} /><Result s={r.status} /></span>
                    </div>
                    <div className="text-xs text-muted-foreground">Required: {r.rule} · Reported: <Value v={r.actual} />{r.controls.length ? ` · ${r.controls.join(", ")}` : ""}</div>
                    {(r.status === "unknown" || r.status === "na") && r.detail && <div className="text-xs">{r.detail}</div>}
                    {r.status === "excepted" && <div className="text-xs">Exception until {fmtDate(r.exception_until)}: {r.exception_reason}{can("risk.accept") && <Button size="sm" variant="ghost" className="ml-2" onClick={() => unexcept.mutate(r.id)}>Withdraw</Button>}</div>}
                    {r.status === "fail" && can("risk.accept") && <Button size="sm" variant="outline" onClick={() => setExcept(r)}>Grant exception</Button>}
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section title="Reported settings">
            {t.facts.length === 0 ? <p className="text-sm text-muted-foreground">Nothing reported yet.</p> : (
              <KeyValue items={t.facts.map((f: any) => [f.title, <Value key={f.key} v={f.value} />])} />
            )}
          </Section>
          <Section title="History">
            {t.history.length === 0 ? <p className="text-sm text-muted-foreground">No reports yet.</p> : (
              <ul className="space-y-2 text-sm">
                {t.history.slice(0, 30).map((h: any) => (
                  <li key={h.id} className="rounded-md border px-3 py-2">
                    <div className="flex flex-wrap justify-between gap-2"><span>{fmtDate(h.at, true)} · {h.source === "agent" ? "agent report" : h.source === "upload" ? "upload" : "re-checked"}</span>
                      <span className="text-xs text-muted-foreground">{h.counts.fail ?? 0} failing · {h.counts.unknown ?? 0} unknown · {h.counts.pass ?? 0} passing</span></div>
                    {h.changes.length > 0 && <ul className="mt-1 text-xs">{h.changes.map((c: any) => <li key={c.key}>{titleForKey(catalogue, t.platform, c.key)}: {resultLabel(c.from)} → {resultLabel(c.to)}</li>)}</ul>}
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </div>
      )}
      {except && <ExceptionDialog result={except} onClose={() => setExcept(null)} />}
    </Sheet>
  );
}

function titleForKey(catalogue: any, platform: string, key: string): string {
  return catalogue.platforms.find((p: any) => p.key === platform)?.settings.find((s: Setting) => s.key === key)?.title ?? key;
}

function ExceptionDialog({ result, onClose }: { result: any; onClose: () => void }) {
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState<string | null>(null);
  const save = useAction(() => api(`/config/findings/${result.id}/exception`, { method: "POST", body: { reason, until } }), { success: "Exception granted.", invalidate: INV, onSuccess: onClose });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Exception: ${result.title}`} description="The result stays visible as excepted until the end date, then fails again."
      footer={<Button disabled={!reason.trim() || !until} loading={save.isPending} onClick={() => save.mutate(undefined)}>Grant exception</Button>}>
      <div className="space-y-4">
        <Field label="Reason" required><Textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why this host may differ, and what compensates for it" /></Field>
        <Field label="Until" required hint="At most a year from today."><DateInput ariaLabel="Until" value={until} onChange={setUntil} /></Field>
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------- baselines

function Baselines({ catalogue }: { catalogue: any }) {
  const { data } = useApi<any[]>("/config/baselines");
  const { can } = useAuth();
  const [creating, setCreating] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const label = (k: string) => catalogue.platforms.find((p: any) => p.key === k)?.label ?? k;
  return (
    <>
      <DataTable rows={data ?? []} rowKey={(b: any) => b.id} onRowClick={(b: any) => setOpen(b.id)} rowLabel={(b: any) => b.name} empty="No baselines yet."
        toolbar={can("integration.manage") && <Button onClick={() => setCreating(true)}><Plus /> New baseline</Button>}
        columns={[
          { key: "n", header: "Name", mobile: "heading", cell: (b: any) => <span className="font-medium">{b.name}</span>, sort: (b: any) => b.name },
          { key: "p", header: "Platform", cell: (b: any) => label(b.platform), sort: (b: any) => b.platform },
          { key: "r", header: "Rules", cell: (b: any) => `${b.enabled_rules} of ${b.rules} on` },
          { key: "d", header: "Applies to", cell: (b: any) => (b.is_default ? "Every target of the platform without its own baseline" : "Targets assigned to it") },
          { key: "e", header: "Status", cell: (b: any) => (b.enabled ? <Badge tone="good">On</Badge> : <Badge tone="outline">Off</Badge>) },
        ]} />
      {creating && <NewBaseline catalogue={catalogue} onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); setOpen(id); }} />}
      {open && <BaselineEditor id={open} catalogue={catalogue} onClose={() => setOpen(null)} />}
    </>
  );
}

function NewBaseline({ catalogue, onClose, onCreated }: { catalogue: any; onClose: () => void; onCreated: (id: number) => void }) {
  const [form, setForm] = useState({ name: "", platform: "windows", description: "", recommended: true });
  const save = useAction(() => api<any>("/config/baselines", { body: form }), { success: "Baseline created.", invalidate: INV, onSuccess: (b) => onCreated(b.id) });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title="New baseline" footer={<Button disabled={!form.name.trim()} loading={save.isPending} onClick={() => save.mutate(undefined)}>Create</Button>}>
      <div className="space-y-4">
        <Field label="Name" required><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Windows workstations" /></Field>
        <Field label="Platform"><Select ariaLabel="Platform" value={form.platform} onChange={(v) => setForm({ ...form, platform: v ?? "windows" })} options={catalogue.platforms.map((p: any) => ({ value: p.key, label: p.label }))} /></Field>
        <Field label="Description"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <Switch checked={form.recommended} onChange={(v) => setForm({ ...form, recommended: v })} label="Start with the recommended settings" />
      </div>
    </Dialog>
  );
}

function BaselineEditor({ id, catalogue, onClose }: { id: number; catalogue: any; onClose: () => void }) {
  const { data: b } = useApi<any>(`/config/baselines/${id}`);
  const { can } = useAuth();
  const edit = can("integration.manage");
  const [adding, setAdding] = useState<string | null>(null);
  const [editing, setEditing] = useState<any>(null);
  const patch = useAction((v: any) => api(`/config/baselines/${id}`, { method: "PATCH", body: v }), { success: "Saved.", invalidate: INV });
  const remove = useAction(() => api(`/config/baselines/${id}`, { method: "DELETE" }), { success: "Baseline deleted.", invalidate: INV, onSuccess: onClose });
  const toggle = useAction((r: any) => api(`/config/rules/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } }), { invalidate: INV });
  const drop = useAction((r: any) => api(`/config/rules/${r.id}`, { method: "DELETE" }), { success: "Rule removed.", invalidate: INV });
  const settings: Setting[] = useMemo(() => catalogue.platforms.find((p: any) => p.key === b?.platform)?.settings ?? [], [catalogue, b]);
  const unused = settings.filter((s) => !b?.rules.some((r: any) => r.key === s.key));
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} extraWide title={b?.name ?? "…"} description={b && catalogue.platforms.find((p: any) => p.key === b.platform)?.label}
      footer={b && edit && <Button variant="outline" loading={remove.isPending} onClick={() => window.confirm(`Delete the baseline “${b.name}”? Its results are removed.`) && remove.mutate(undefined)}><Trash2 /> Delete baseline</Button>}>
      {!b ? <Skeleton className="h-64" /> : (
        <div className="space-y-5">
          {edit && (
            <div className="flex flex-wrap gap-6">
              <Switch checked={b.enabled} onChange={(v) => patch.mutate({ enabled: v })} label="Baseline on" />
              <Switch checked={b.is_default} onChange={(v) => patch.mutate({ is_default: v })} label="Default for this platform" />
            </div>
          )}
          <DataTable rows={b.rules} rowKey={(r: any) => r.id} rowLabel={(r: any) => r.title} empty="No rules yet."
            toolbar={edit && unused.length > 0 && <Select ariaLabel="Add a rule" value={null} placeholder="Add a rule…" onChange={(v) => setAdding(v)} options={unused.map((s) => ({ value: s.key, label: s.title }))} className="w-72" />}
            columns={[
              { key: "t", header: "Setting", mobile: "heading", cell: (r: any) => <span className={r.enabled ? "" : "text-muted-foreground line-through"}>{r.title}</span>, sort: (r: any) => r.title },
              { key: "r", header: "Required", cell: (r: any) => r.rule },
              { key: "s", header: "Severity", cell: (r: any) => <Sev s={r.severity} />, sort: (r: any) => ["critical", "high", "medium", "low"].indexOf(r.severity) },
              { key: "c", header: "Controls", cell: (r: any) => <span className="text-xs">{r.controls.join(", ") || "—"}</span> },
              ...(edit ? [{ key: "a", header: "", cell: (r: any) => (
                <span className="flex justify-end gap-1">
                  <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>Edit</Button>
                  <Button size="sm" variant="ghost" onClick={() => toggle.mutate(r)}>{r.enabled ? "Turn off" : "Turn on"}</Button>
                  <Button size="sm" variant="ghost" aria-label={`Remove ${r.title}`} onClick={() => drop.mutate(r)}><Trash2 /></Button>
                </span>) }] : []),
            ]} />
        </div>
      )}
      {(adding || editing) && b && (
        <RuleDialog baselineId={id} setting={settings.find((s) => s.key === (editing?.key ?? adding))!} rule={editing} severities={catalogue.severities} operators={catalogue.operators}
          onClose={() => { setAdding(null); setEditing(null); }} />
      )}
    </Dialog>
  );
}

function RuleDialog({ baselineId, setting, rule, severities, operators, onClose }: { baselineId: number; setting: Setting; rule?: any; severities: string[]; operators: Record<string, string>; onClose: () => void }) {
  const rec = setting.recommended;
  const [op, setOp] = useState<string>(rule?.operator ?? rec?.operator ?? setting.operators[0]);
  const [value, setValue] = useState<string>(expectedToInput(rule ? rule.expected : rec?.expected));
  const [severity, setSeverity] = useState<string>(rule?.severity ?? rec?.severity ?? "medium");
  const [controls, setControls] = useState<string>((rule?.controls ?? rec?.controls ?? []).join(", "));
  const needsValue = !["is_true", "is_false", "empty"].includes(op);
  const body = { operator: op, expected: expectedFromInput(setting, op, value), severity, controls: controls.split(/[,\s]+/).filter(Boolean) };
  const save = useAction(() => (rule ? api(`/config/rules/${rule.id}`, { method: "PATCH", body }) : api(`/config/baselines/${baselineId}/rules`, { body: { key: setting.key, ...body } })),
    { success: "Rule saved.", invalidate: INV, onSuccess: onClose });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={setting.title} description={setting.description}
      footer={<Button disabled={needsValue && !value.trim()} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save rule</Button>}>
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Requirement"><Select ariaLabel="Operator" value={op} onChange={(v) => setOp(v ?? op)} options={setting.operators.map((o) => ({ value: o, label: operators[o] }))} /></Field>
          {needsValue && <Field label="Value" hint={op === "in" || op === "not_in" ? "Separate values with commas." : setting.choices.length ? `One of: ${setting.choices.join(", ")}` : undefined}><Input value={value} onChange={(e) => setValue(e.target.value)} /></Field>}
        </div>
        <Field label="Severity"><Select ariaLabel="Severity" value={severity} onChange={(v) => setSeverity(v ?? severity)} options={severities.map((s) => ({ value: s, label: titleCase(s) }))} /></Field>
        <Field label="Controls" hint="Keystone control codes, e.g. KC-TEC-20. A baseline met on every target is filed as evidence for them."><Input value={controls} onChange={(e) => setControls(e.target.value)} /></Field>
        <p className="text-sm text-muted-foreground">Passes when the setting {describeExpected(operators, op, body.expected)}.{setting.requires ? " Not applicable when its prerequisite is off." : ""}</p>
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------- agents

function Agents() {
  const { data } = useApi<any>("/config/agent");
  const rotate = useAction(() => api("/config/agent/rotate", { method: "POST" }), { success: "New enrolment key. Agents already installed keep working.", invalidate: ["/config/agent"] });
  const hours = useAction((h: number) => api("/config/agent", { method: "PATCH", body: { report_hours: h } }), { success: "Saved. Installed agents keep their schedule until reinstalled.", invalidate: ["/config"] });
  if (!data) return <Skeleton className="h-64" />;
  return (
    <div className="max-w-4xl space-y-6">
      {!data.https && (
        <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-[#b07400]" />
          <div>Keystone's address is {data.server}. Agents only talk to HTTPS addresses (HTTP works for localhost testing only). Set KEYSTONE_PUBLIC_URL to the HTTPS address users reach Keystone on.</div></div>
      )}
      <p className="text-sm text-muted-foreground">The agents only read settings and send them to Keystone. They never change the host, and Keystone can't send them commands. Each agent swaps the enrolment key for its own device token when it enrols, and the token can only send reports for that host.</p>
      {(["windows", "linux"] as const).map((p) => (
        <Card key={p}>
          <CardHeader title={p === "windows" ? "Windows" : "Linux"} description={p === "windows" ? "PowerShell 5.1 or later. Installs a scheduled task that runs as SYSTEM at startup and every few hours." : "Any distribution with sh and curl. Installs a systemd timer, or a cron job where there's no systemd."}
            action={<a href={downloadUrl(`/config/agent/download/${p}`)}><Button size="sm" variant="outline"><Download /> {data.files[p].filename}</Button></a>} />
          <CardBody className="space-y-3 text-sm">
            <div className="text-xs text-muted-foreground">SHA-256 <span className="break-all font-mono">{data.files[p].sha256}</span></div>
            <Field label={p === "windows" ? "Install from an elevated PowerShell prompt in the download folder" : "Install as root in the download folder"}>
              <div className="flex items-start gap-2"><code className="block min-w-0 flex-1 break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">{data.install[p]}</code><CopyButton text={data.install[p]} /></div>
            </Field>
            <div className="text-xs text-muted-foreground">To remove: <code className="font-mono">{data.uninstall[p]}</code></div>
          </CardBody>
        </Card>
      ))}
      <Card>
        <CardHeader title="Enrolment key" description={data.rotated_at ? `Created ${fmtDate(data.rotated_at, true)}` : undefined}
          action={<Button size="sm" variant="outline" loading={rotate.isPending} onClick={() => window.confirm("Create a new enrolment key? The current one stops working for new installs.") && rotate.mutate(undefined)}><RotateCcw /> New key</Button>} />
        <CardBody className="space-y-3 text-sm">
          <div className="flex items-center gap-2"><KeyRound className="size-4 text-muted-foreground" /><code className="break-all font-mono text-xs">{data.enrolment_key}</code><CopyButton text={data.enrolment_key} /></div>
          <p className="text-muted-foreground">Anyone with this key can enrol a device, so share it only with the people installing agents and replace it when they're done. Revoke a device's token from its page under Hosts and firewalls.</p>
          <Field label="Report every"><Select ariaLabel="Report interval" value={String(data.report_hours)} onChange={(v) => v && hours.mutate(Number(v))} options={[1, 2, 4, 8, 12, 24].map((h) => ({ value: String(h), label: `${h} hour${h > 1 ? "s" : ""}` }))} className="w-40" /></Field>
        </CardBody>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------- firewall uploads

const EXPORT_HELP: Record<string, string> = {
  fortigate: "Back up the configuration (System > Configuration > Backup), or run show full-configuration for complete results.",
  panos: "Export the running configuration (Device > Setup > Operations > Export named configuration snapshot: running-config.xml).",
  cisco: "Save the output of show running-config as a text file (ASA or IOS).",
  pfsense: "Download config.xml (Diagnostics > Backup & Restore). Works for OPNsense too.",
};

function UploadFirewall({ catalogue }: { catalogue: any }) {
  const [platform, setPlatform] = useState("fortigate");
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState<string | null>(null);
  const [, setParams] = useSearchParams();
  const { data: targets } = useApi<any[]>("/config/targets");
  const existing = (targets ?? []).filter((t) => t.kind === "firewall" && t.platform === platform);
  const send = useAction(async () => {
    const fd = new FormData();
    fd.append("platform", platform);
    fd.append("file", file as File);
    if (targetId) fd.append("target_id", targetId); else if (name.trim()) fd.append("name", name.trim());
    return upload<any>("/config/firewalls", fd);
  }, { success: (r: any) => `${r.target.name}: ${r.result.fail} failing, ${r.result.unknown} unknown, ${r.result.pass} passing.`, invalidate: INV,
    onSuccess: (r: any) => setParams({ tab: "targets", target: String(r.target.id) }) });
  return (
    <div className="max-w-2xl space-y-4">
      <p className="text-sm text-muted-foreground">Keystone reads the settings it checks from the file and keeps only those values and the file's SHA-256. The file itself is not stored: configuration exports contain password hashes and keys.</p>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Firewall"><Select ariaLabel="Firewall platform" value={platform} onChange={(v) => { setPlatform(v ?? "fortigate"); setTargetId(null); }} options={catalogue.platforms.filter((p: any) => p.kind === "firewall").map((p: any) => ({ value: p.key, label: p.label }))} /></Field>
        <Field label="Update"><Select ariaLabel="Existing firewall" value={targetId} onChange={setTargetId} allowEmpty emptyLabel="A new firewall" options={existing.map((t) => ({ value: String(t.id), label: t.name }))} /></Field>
      </div>
      <p className="text-xs text-muted-foreground">{EXPORT_HELP[platform]}</p>
      {!targetId && <Field label="Name" hint="Defaults to the host name in the file."><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>}
      <Field label="Configuration file" hint="Up to 10 MB.">
        <input type="file" accept=".conf,.cfg,.txt,.xml,.log" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" aria-label="Configuration file" />
      </Field>
      <Button disabled={!file} loading={send.isPending} onClick={() => send.mutate(undefined)}><Upload /> Check configuration</Button>
    </div>
  );
}
