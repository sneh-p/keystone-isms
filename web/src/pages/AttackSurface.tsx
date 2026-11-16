import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Crosshair, Plus, RefreshCw, ShieldOff } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople, useUrlFilter } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, KeyValue, PageHeader, Progress, Section, Skeleton, Stat, Switch } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { DateInput } from "@/components/forms";
import { ImportButton } from "@/components/ImportDialog";

const SEV_TONE: Record<string, "critical" | "warning" | "primary" | "outline"> = { critical: "critical", high: "warning", medium: "primary", low: "outline" };
const SOURCE_LABEL: Record<string, string> = { rmm: "RMM", edr: "EDR", vuln: "Scanner", mdm: "MDM", manual: "CSV" };

function Sev({ s }: { s: string }) {
  return <Badge tone={SEV_TONE[s] ?? "outline"}>{titleCase(s)}</Badge>;
}

function YesNo({ v }: { v: boolean | null | undefined }) {
  if (v === null || v === undefined) return <span className="text-muted-foreground">Unknown</span>;
  return v ? <span className="text-[#0a7a0a] dark:text-good">Yes</span> : <span className="font-medium text-critical">No</span>;
}

/** Attack surface management: what the connected tools report, the organisation's baselines, and the gaps. */
export default function AttackSurface() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? (params.get("finding") || params.get("baseline") ? "findings" : "overview");
  const { data } = useApi<any>("/asm/overview");
  const { can } = useAuth();
  const evaluate = useAction(() => api("/asm/evaluate", { method: "POST" }), { success: (r: any) => `Baselines checked: ${r.new_findings} new finding(s).`, invalidate: ["/asm", "/dashboard"] });
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Crosshair} title="Attack surface" description="Devices, accounts, vulnerabilities and settings from your connected tools, checked against the baselines you set. Gaps become findings and alert their owners."
        actions={can("integration.manage") && <>
          <ImportButton register="devices" noun="devices" invalidate={["/asm", "/dashboard"]} />
          <Button variant="outline" loading={evaluate.isPending} onClick={() => evaluate.mutate(undefined)}><RefreshCw /> Check now</Button>
        </>} />
      <Tabs value={tab} onValueChange={(v) => setParams({ tab: v })} tabs={[
        { value: "overview", label: "Overview", content: <Overview data={data} /> },
        { value: "findings", label: `Findings (${data.findings_total})`, content: <Findings /> },
        { value: "devices", label: `Devices (${data.devices})`, content: <Devices /> },
        { value: "identities", label: `Identities (${data.identities})`, content: <Identities /> },
        { value: "settings", label: "Configuration", content: <Settings /> },
        { value: "baselines", label: "Baselines", content: <Baselines /> },
      ]} />
    </div>
  );
}

function Overview({ data }: { data: any }) {
  const { can } = useAuth();
  const add = useAction(() => api("/asm/baselines/recommended", { method: "POST" }), { success: (r: any) => `${r.added} baseline(s) added.`, invalidate: ["/asm", "/dashboard"] });
  const cov = data.coverage;
  if (!data.sources.length && !data.devices) {
    return (
      <Empty icon={Crosshair} title="Connect your tools to see your attack surface"
        action={<div className="flex flex-wrap justify-center gap-2"><Link to="/integrations"><Button>Connect a source</Button></Link>{can("integration.manage") && <Button variant="outline" loading={add.isPending} onClick={() => add.mutate(undefined)}>Add recommended baselines</Button>}</div>}>
        Connect Microsoft 365, your EDR, RMM or vulnerability scanner (read-only), or import devices from CSV. Then set baselines: what every device and account must have.
      </Empty>
    );
  }
  const pct = (c: any) => (c.pct === null ? "—" : `${c.pct}%`);
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="Devices" value={data.devices} hint={Object.entries(data.by_type).map(([k, v]) => `${v} ${k}`).join(" · ")} to="/attack-surface?tab=devices" />
        <Stat label="With an EDR agent" value={pct(cov.edr)} hint={`${cov.edr.covered} of ${cov.edr.total} workstations and servers`} tone={cov.edr.pct !== null && cov.edr.pct < 100 ? "warning" : "good"} />
        <Stat label="Critical or high findings" value={data.findings.critical + data.findings.high} tone={data.findings.critical ? "critical" : data.findings.high ? "warning" : "good"} to="/attack-surface?tab=findings" hint={`${data.findings_total} open in total`} />
        <Stat label="Accounts with MFA" value={data.mfa.known ? `${Math.round((100 * data.mfa.registered) / data.mfa.known)}%` : "—"} hint={data.mfa.known ? `${data.mfa.registered} of ${data.mfa.known} enabled accounts` : "No identity source yet"} to="/attack-surface?tab=identities" />
      </div>
      <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
        <Card>
          <CardHeader title="Coverage" description="Workstations and servers seen by each kind of tool." />
          <CardBody className="space-y-4">
            {[["edr", "EDR agent"], ["rmm", "Managed by RMM"], ["vuln", "Scanned for vulnerabilities"], ["mdm", "Device management"]].map(([k, label]) => (
              <div key={k}>
                <div className="mb-1 flex justify-between text-sm"><span>{label}</span><span className="text-muted-foreground">{cov[k].covered} of {cov[k].total}</span></div>
                <Progress label={`${label} coverage`} value={cov[k].pct ?? 0} tone={cov[k].pct === 100 ? "good" : "primary"} />
              </div>
            ))}
            <div className="border-t pt-3 text-sm">
              <div className="mb-1 font-medium">Open vulnerabilities</div>
              <div className="flex flex-wrap gap-2">{Object.entries(data.vulnerabilities).map(([s, n]: any) => <span key={s} className="flex items-center gap-1"><Sev s={s} /> {n}</span>)}</div>
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Baselines" description="Share of items in scope that meet each requirement." action={<Link to="/attack-surface?tab=baselines" className="text-sm text-primary hover:underline">Manage</Link>} />
          <CardBody className="p-0">
            {data.baselines.length === 0 ? <div className="p-5 text-sm text-muted-foreground">No baselines yet. {can("integration.manage") && <Button size="sm" variant="outline" className="ml-2" loading={add.isPending} onClick={() => add.mutate(undefined)}>Add recommended baselines</Button>}</div> : (
              <ul className="divide-y">
                {data.baselines.filter((b: any) => b.enabled).map((b: any) => (
                  <li key={b.id}>
                    <Link to={`/attack-surface?tab=findings&baseline=${b.id}`} className="grid grid-cols-[minmax(0,1fr)_7rem] items-center gap-3 px-5 py-2.5 text-sm hover:bg-muted/50">
                      <span className="min-w-0"><span className="mr-2"><Sev s={b.severity} /></span>{b.name}<span className="block text-xs text-muted-foreground">{b.in_scope ? `${b.open} open of ${b.in_scope}${b.excepted ? ` · ${b.excepted} excepted` : ""}` : "Nothing in scope yet"}</span></span>
                      <span>{b.pct === null ? <span className="text-xs text-muted-foreground">—</span> : <><span className="text-xs">{b.pct}%</span><Progress label={`${b.name} compliance`} value={b.pct} tone={b.pct === 100 ? "good" : b.severity === "critical" ? "critical" : "primary"} /></>}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
      <Card>
        <CardHeader title="Sources" description="Read-only connections; each run refreshes the data and re-checks the baselines." action={<Link to="/integrations" className="text-sm text-primary hover:underline">Integrations</Link>} />
        <CardBody className="p-0">
          {data.sources.length === 0 ? <div className="p-5 text-sm text-muted-foreground">No sources connected; devices come from CSV imports only.</div> : (
            <ul className="divide-y">{data.sources.map((s: any) => (
              <li key={s.id} className="flex flex-wrap items-center justify-between gap-2 px-5 py-2.5 text-sm">
                <span><span className="font-medium">{s.name}</span> <span className="text-xs text-muted-foreground">{s.provider} · {s.categories.join(", ")}</span></span>
                <span className="text-xs">{s.last_status === "error" ? <span className="text-critical">Failed: {s.last_error}</span> : s.last_run_at ? `Last run ${fmtDate(s.last_run_at, true)}` : "Not run yet"}</span>
              </li>
            ))}</ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function Findings() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [status, setStatus] = useUrlFilter("status");
  const [severity, setSeverity] = useUrlFilter("severity");
  const [baseline, setBaseline] = useUrlFilter("baseline");
  const [focus] = useUrlFilter("finding");
  const q = new URLSearchParams({ status: status ?? "open", ...(severity ? { severity } : {}), ...(baseline ? { baseline_id: baseline } : {}) });
  const { data } = useApi<any[]>(`/asm/findings?${q}`);
  const bl = useApi<any>("/asm/baselines");
  const [exc, setExc] = useState<any>(null);
  const grant = useAction(() => api(`/asm/findings/${exc.id}/exception`, { body: { reason: exc.reason, until: exc.until } }), { success: "Exception approved.", invalidate: ["/asm", "/dashboard"], onSuccess: () => setExc(null) });
  const revoke = useAction((id: number) => api(`/asm/findings/${id}/revoke-exception`, { method: "POST" }), { success: "Exception revoked.", invalidate: ["/asm"] });
  const rows = useMemo(() => (data ?? []).slice().sort((a, b) => (String(a.id) === focus ? -1 : String(b.id) === focus ? 1 : 0)), [data, focus]);
  if (!data) return <Skeleton className="h-64" />;
  return (
    <>
      <DataTable rows={rows} rowKey={(f: any) => f.id} search={(f: any) => `${f.entity} ${f.baseline}`} empty="No findings match. Everything in scope meets its baselines."
        toolbar={<>
          <div className="w-40"><Select value={status} onChange={setStatus} allowEmpty emptyLabel="Open" placeholder="Status" ariaLabel="Status" options={[{ value: "excepted", label: "Excepted" }, { value: "resolved", label: "Resolved" }]} /></div>
          <div className="w-40"><Select value={severity} onChange={setSeverity} allowEmpty emptyLabel="Any severity" placeholder="Severity" ariaLabel="Severity" options={["critical", "high", "medium", "low"].map((s) => ({ value: s, label: titleCase(s) }))} /></div>
          <div className="w-64"><Select value={baseline} onChange={setBaseline} allowEmpty emptyLabel="All baselines" placeholder="Baseline" ariaLabel="Baseline" options={(bl.data?.baselines ?? []).map((b: any) => ({ value: String(b.id), label: b.name }))} /></div>
        </>}
        columns={[
          { key: "s", header: "Severity", cell: (f: any) => <Sev s={f.severity} />, sort: (f: any) => ["critical", "high", "medium", "low"].indexOf(f.severity), className: "w-24" },
          { key: "e", header: "Device or account", sort: (f: any) => f.entity, cell: (f: any) => (
            <div className={String(f.id) === focus ? "rounded bg-primary/10 px-1" : undefined}>
              <div className="font-medium">{f.entity_type === "device" ? <Link to={`/attack-surface?tab=devices&device=${f.entity_id}`} className="hover:underline">{f.entity}</Link> : f.entity}</div>
              <div className="text-xs text-muted-foreground">{titleCase(f.entity_type)}{f.owner_user_id ? ` · ${name(f.owner_user_id)}` : " · no owner"}</div>
            </div>
          ) },
          { key: "b", header: "Baseline", cell: (f: any) => <div><div>{f.baseline}</div><div className="text-xs text-muted-foreground">{f.no_data ? "No connected tool reports this" : f.detail}</div></div>, sort: (f: any) => f.baseline },
          { key: "f", header: "Since", cell: (f: any) => fmtDate(f.first_seen), sort: (f: any) => f.first_seen },
          { key: "x", header: "", cell: (f: any) => f.status === "excepted"
            ? <div className="text-xs"><div>Excepted until {fmtDate(f.exception_until)} by {name(f.exception_by_id)}</div><div className="text-muted-foreground">{f.exception_reason}</div>{can("risk.accept") && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(f.id)}>Revoke</Button>}</div>
            : f.status === "open" && can("risk.accept") ? <Button size="sm" variant="ghost" onClick={() => setExc({ id: f.id, label: `${f.entity}: ${f.baseline}`, reason: "", until: null })}><ShieldOff /> Exception</Button> : null },
        ]} />
      <Dialog open={!!exc} onOpenChange={(o) => !o && setExc(null)} title="Approve an exception" description={exc?.label}
        footer={<Button disabled={!exc?.reason?.trim() || !exc?.until} loading={grant.isPending} onClick={() => grant.mutate(undefined)}>Approve exception</Button>}>
        {exc && <div className="space-y-3">
          <Field label="Why this is acceptable" required><Textarea value={exc.reason} onChange={(e) => setExc({ ...exc, reason: e.target.value })} maxLength={2000} placeholder="e.g. Kiosk in a locked room; replaced in Q1" /></Field>
          <Field label="Until" required hint="At most a year. The finding reopens when the exception ends. You can't approve one for your own device or account."><DateInput value={exc.until} onChange={(v) => setExc({ ...exc, until: v })} /></Field>
        </div>}
      </Dialog>
    </>
  );
}

function Devices() {
  const { name } = usePeople();
  const [open, setOpen] = useUrlFilter("device");
  const { data } = useApi<any[]>("/asm/devices");
  if (!data) return <Skeleton className="h-64" />;
  return (
    <>
      <DataTable rows={data} rowKey={(d: any) => d.id} rowLabel={(d: any) => d.name} onRowClick={(d: any) => setOpen(String(d.id))} search={(d: any) => `${d.name} ${d.serial ?? ""} ${d.owner_email ?? ""} ${d.os ?? ""}`}
        empty="No devices yet. Connect a source or import a CSV."
        columns={[
          { key: "n", header: "Device", sort: (d: any) => d.name, cell: (d: any) => <div><div className="font-medium">{d.name}</div><div className="text-xs text-muted-foreground">{[titleCase(d.device_type), d.os].filter(Boolean).join(" · ")}</div></div> },
          { key: "o", header: "Owner", cell: (d: any) => (d.owner_user_id ? name(d.owner_user_id) : d.owner_email ?? <span className="text-muted-foreground">Unknown</span>) },
          { key: "src", header: "Seen by", cell: (d: any) => <div className="flex flex-wrap gap-1">{d.sources.map((s: string) => <Badge key={s} tone="outline">{SOURCE_LABEL[s] ?? s}</Badge>)}</div> },
          { key: "e", header: "EDR", cell: (d: any) => <YesNo v={d.edr} /> },
          { key: "enc", header: "Encrypted", cell: (d: any) => <YesNo v={d.encrypted} /> },
          { key: "v", header: "Critical vulns", sort: (d: any) => d.critical_vulns ?? -1, cell: (d: any) => (d.critical_vulns ? <span className="font-medium text-critical">{d.critical_vulns}</span> : d.critical_vulns === 0 ? "0" : <span className="text-muted-foreground">—</span>) },
          { key: "l", header: "Last seen", sort: (d: any) => d.last_seen ?? "", cell: (d: any) => fmtDate(d.last_seen) },
          { key: "f", header: "Findings", sort: (d: any) => d.open_findings, cell: (d: any) => (d.open_findings ? <Badge tone="warning">{d.open_findings} open</Badge> : <span className="text-muted-foreground">None</span>) },
        ]} />
      {open && <DeviceDrawer id={Number(open)} onClose={() => setOpen(null)} />}
    </>
  );
}

function DeviceDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { name } = usePeople();
  const { data } = useApi<any>(`/asm/devices/${id}`);
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data?.name ?? "Loading…"} subtitle={data && [titleCase(data.device_type), data.os, data.os_version].filter(Boolean).join(" · ")}>
      {!data ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <KeyValue items={[["Owner", data.owner_user_id ? name(data.owner_user_id) : data.owner_email ?? "Unknown"], ["Serial", data.serial], ["Host name", data.hostname], ["First seen", fmtDate(data.first_seen)], ["Last seen", fmtDate(data.last_seen, true)]]} />
          <Section title="What the tools report">
            <ul className="divide-y rounded-md border text-sm">
              {data.properties.map((p: any) => (
                <li key={p.key} className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 px-3 py-1.5">
                  <span>{p.label}<span className="block text-xs text-muted-foreground">{p.source}{p.at ? ` · ${fmtDate(p.at, true)}` : ""}</span></span>
                  <span className="text-right">{typeof p.value === "boolean" ? <YesNo v={p.value} /> : p.value}</span>
                </li>
              ))}
            </ul>
          </Section>
          <Section title={`Findings (${data.findings.filter((f: any) => f.status === "open").length} open)`}>
            {data.findings.length === 0 ? <p className="text-sm text-muted-foreground">Meets every baseline in scope.</p> : (
              <ul className="space-y-1.5 text-sm">{data.findings.map((f: any) => <li key={f.id} className="flex items-start gap-2"><Sev s={f.severity} /><span>{f.baseline} <span className="text-xs text-muted-foreground">({titleCase(f.status)}{f.no_data ? ", no data" : ""})</span></span></li>)}</ul>
            )}
          </Section>
          <Section title={`Open vulnerabilities (${data.vulnerabilities.length})`}>
            {data.vulnerabilities.length === 0 ? <p className="text-sm text-muted-foreground">None reported.</p> : (
              <ul className="divide-y rounded-md border text-sm">{data.vulnerabilities.slice(0, 100).map((v: any) => (
                <li key={v.id} className="flex items-start gap-2 px-3 py-1.5"><Sev s={v.severity} /><span className="min-w-0 flex-1">{v.title}<span className="block text-xs text-muted-foreground">{[v.cve, v.cvss && `CVSS ${v.cvss}`, v.exploitable && "exploit known", v.first_seen && `since ${fmtDate(v.first_seen)}`, v.source].filter(Boolean).join(" · ")}</span></span></li>
              ))}</ul>
            )}
          </Section>
          <Section title="Sources">
            <ul className="space-y-1 text-sm">{data.sources.map((s: any, i: number) => <li key={i}>{s.name} <span className="text-xs text-muted-foreground">({SOURCE_LABEL[s.category] ?? s.category}) · collected {fmtDate(s.collected_at, true)}</span></li>)}</ul>
          </Section>
        </div>
      )}
    </Sheet>
  );
}

function Identities() {
  const { data } = useApi<any[]>("/asm/identities");
  if (!data) return <Skeleton className="h-64" />;
  return (
    <DataTable rows={data} rowKey={(i: any) => i.id} search={(i: any) => `${i.upn} ${i.display_name ?? ""}`} empty="No identity source connected yet (Microsoft 365)."
      columns={[
        { key: "u", header: "Account", sort: (i: any) => i.upn, cell: (i: any) => <div><div className="font-medium">{i.display_name ?? i.upn}</div><div className="text-xs text-muted-foreground">{i.upn}</div></div> },
        { key: "m", header: "MFA", cell: (i: any) => <YesNo v={i.mfa_registered} /> },
        { key: "a", header: "Admin", cell: (i: any) => (i.is_admin ? <Badge tone="warning">Admin</Badge> : i.is_admin === false ? "No" : <span className="text-muted-foreground">Unknown</span>) },
        { key: "e", header: "Enabled", cell: (i: any) => <YesNo v={i.account_enabled} /> },
        { key: "g", header: "Guest", cell: (i: any) => (i.is_guest ? "Guest" : "Member") },
        { key: "s", header: "Last sign-in", sort: (i: any) => i.last_sign_in_days ?? 9999, cell: (i: any) => (i.last_sign_in_days === null || i.last_sign_in_days === undefined ? <span className="text-muted-foreground">Unknown</span> : `${i.last_sign_in_days} days ago`) },
        { key: "f", header: "Findings", sort: (i: any) => i.open_findings, cell: (i: any) => (i.open_findings ? <Badge tone="warning">{i.open_findings} open</Badge> : "None") },
      ]} />
  );
}

function Settings() {
  const { data } = useApi<any[]>("/asm/settings");
  if (!data) return <Skeleton className="h-64" />;
  return (
    <DataTable rows={data} rowKey={(s: any) => s.id} search={(s: any) => `${s.title} ${s.category ?? ""}`} empty="No configuration data yet (Microsoft Secure Score comes from the Microsoft 365 source)."
      columns={[
        { key: "t", header: "Setting", sort: (s: any) => s.title, cell: (s: any) => <div><div className="font-medium">{s.title}</div><div className="text-xs text-muted-foreground">{s.category}</div></div> },
        { key: "c", header: "Meets target", sort: (s: any) => (s.compliant === null ? 2 : s.compliant ? 1 : 0), cell: (s: any) => <YesNo v={s.compliant} /> },
        { key: "d", header: "Detail", cell: (s: any) => <span className="text-sm text-muted-foreground">{s.detail}</span> },
      ]} />
  );
}

function Baselines() {
  const { can } = useAuth();
  const { data } = useApi<any>("/asm/baselines");
  const controls = useApi<any[]>("/controls");
  const [edit, setEdit] = useState<any>(null);
  const ed = can("integration.manage");
  const save = useAction((b: any) => (b.id ? api(`/asm/baselines/${b.id}`, { method: "PATCH", body: strip(b) }) : api("/asm/baselines", { body: strip(b) })), { success: "Baseline saved and checked.", invalidate: ["/asm", "/dashboard"], onSuccess: () => setEdit(null) });
  const toggle = useAction((b: any) => api(`/asm/baselines/${b.id}`, { method: "PATCH", body: { enabled: !b.enabled } }), { invalidate: ["/asm", "/dashboard"] });
  const add = useAction(() => api("/asm/baselines/recommended", { method: "POST" }), { success: (r: any) => `${r.added} baseline(s) added.`, invalidate: ["/asm", "/dashboard"] });
  if (!data) return <Skeleton className="h-64" />;
  const props = data.properties.filter((p: any) => !edit || p.entity === edit.entity);
  const prop = data.properties.find((p: any) => p.key === edit?.property);
  return (
    <>
      {ed && <div className="mb-3 flex flex-wrap gap-2">
        <Button onClick={() => setEdit({ name: "", entity: "device", property: "disk_encrypted", operator: "is_true", value: null, scope: { device_types: ["workstation"] }, severity: "high", controls: [], missing: "flag", enabled: true })}><Plus /> New baseline</Button>
        <Button variant="outline" loading={add.isPending} onClick={() => add.mutate(undefined)}>Add recommended baselines</Button>
      </div>}
      <DataTable rows={data.baselines} rowKey={(b: any) => b.id} search={(b: any) => b.name} empty="No baselines yet. Add the recommended set and adjust it."
        onRowClick={ed ? (b: any) => setEdit({ ...b }) : undefined}
        columns={[
          { key: "n", header: "Baseline", sort: (b: any) => b.name, cell: (b: any) => <div><div className="font-medium">{b.name}</div><div className="text-xs text-muted-foreground">{titleCase(b.entity)}: {b.rule}{b.scope?.device_types?.length ? ` · ${b.scope.device_types.join(", ")}` : ""}{b.missing === "flag" ? " · missing data counts as a gap" : ""}</div></div> },
          { key: "s", header: "Severity", cell: (b: any) => <Sev s={b.severity} />, sort: (b: any) => ["critical", "high", "medium", "low"].indexOf(b.severity) },
          { key: "c", header: "Controls", cell: (b: any) => <div className="flex flex-wrap gap-1">{b.controls.map((c: string) => <Badge key={c} tone="outline" className="font-mono text-[10px]">{c}</Badge>)}</div> },
          { key: "e", header: "On", cell: (b: any) => <span onClick={(e) => e.stopPropagation()}><Switch checked={b.enabled} onChange={() => toggle.mutate(b)} disabled={!ed} label={b.enabled ? "On" : "Off"} /></span> },
        ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title={edit?.id ? "Edit baseline" : "New baseline"} wide
        footer={<Button disabled={!edit?.name?.trim()} loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button>}>
        {edit && <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" required className="sm:col-span-2"><Input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} maxLength={200} /></Field>
          <Field label="Applies to"><Select value={edit.entity} onChange={(v) => { const first = data.properties.find((p: any) => p.entity === v); setEdit({ ...edit, entity: v, property: first?.key, operator: first?.type === "bool" ? "is_true" : "lte", value: first?.type === "bool" ? null : "0", scope: {} }); }}
            options={[{ value: "device", label: "Devices" }, { value: "identity", label: "Accounts" }, { value: "setting", label: "Configuration settings" }]} /></Field>
          <Field label="Property"><Select value={edit.property} onChange={(v) => { const p = data.properties.find((x: any) => x.key === v); setEdit({ ...edit, property: v, operator: p?.type === "bool" ? "is_true" : "lte", value: p?.type === "bool" ? null : edit.value ?? "0" }); }}
            options={props.map((p: any) => ({ value: p.key, label: p.label }))} /></Field>
          <Field label="Requirement"><Select value={edit.operator} onChange={(v) => setEdit({ ...edit, operator: v })}
            options={(prop?.type === "bool" ? ["is_true", "is_false"] : ["lte", "gte", "eq", "ne"]).map((o) => ({ value: o, label: data.operators[o] }))} /></Field>
          {prop?.type === "int" && <Field label="Value"><Input type="number" value={edit.value ?? ""} onChange={(e) => setEdit({ ...edit, value: e.target.value })} /></Field>}
          {edit.entity === "device" && <Field label="Device types (empty: all)" className="sm:col-span-2"><MultiSelect value={edit.scope?.device_types ?? []} onChange={(v) => setEdit({ ...edit, scope: { ...edit.scope, device_types: v } })} options={["workstation", "server", "mobile", "other"].map((t) => ({ value: t, label: titleCase(t) }))} /></Field>}
          {edit.entity === "identity" && <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={!!edit.scope?.enabled_only} onChange={(e) => setEdit({ ...edit, scope: { ...edit.scope, enabled_only: e.target.checked } })} /> Enabled accounts only</label>}
          <Field label="Severity"><Select value={edit.severity} onChange={(v) => setEdit({ ...edit, severity: v })} options={["critical", "high", "medium", "low"].map((s) => ({ value: s, label: titleCase(s) }))} /></Field>
          <Field label="When no tool reports it" hint="Coverage baselines should count missing data as a gap."><Select value={edit.missing} onChange={(v) => setEdit({ ...edit, missing: v })} options={[{ value: "flag", label: "Count it as a gap" }, { value: "ignore", label: "Ignore" }]} /></Field>
          <Field label="Supports controls" className="sm:col-span-2" hint="When every item meets the baseline, Keystone files evidence on these controls."><MultiSelect value={edit.controls} onChange={(v) => setEdit({ ...edit, controls: v })} options={(controls.data ?? []).map((c) => ({ value: c.code, label: `${c.code} ${c.title}` }))} /></Field>
        </div>}
      </Dialog>
    </>
  );
}

function strip(b: any) {
  const { id: _id, rule: _rule, ...rest } = b;
  return { ...rest, value: rest.value === "" ? null : rest.value };
}

