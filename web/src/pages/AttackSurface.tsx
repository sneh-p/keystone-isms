import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { CheckCircle2, Crosshair, Flame, Globe2, Plus, RefreshCw, ShieldOff, Trash2 } from "lucide-react";
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
import { CopyButton } from "@/components/CopyButton";
import { TicketButton, useTickets } from "@/components/TicketButton";

const SEV_TONE: Record<string, "critical" | "warning" | "primary" | "outline"> = { critical: "critical", high: "warning", medium: "primary", low: "outline" };
const SOURCE_LABEL: Record<string, string> = { rmm: "RMM", edr: "EDR", vuln: "Scanner", mdm: "MDM", posture: "Cloud posture", manual: "CSV" };

function Sev({ s }: { s: string }) {
  return <Badge tone={SEV_TONE[s] ?? "outline"}>{titleCase(s)}</Badge>;
}

function YesNo({ v }: { v: boolean | null | undefined }) {
  if (v === null || v === undefined) return <span className="text-muted-foreground">Unknown</span>;
  return v ? <span className="text-good-fg">Yes</span> : <span className="font-medium text-critical">No</span>;
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
        { value: "vulnerabilities", label: "Vulnerabilities", content: <Vulnerabilities /> },
        { value: "external", label: "Internet-facing", content: <External /> },
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
  const tickets = useTickets("asm_finding", (data ?? []).filter((f: any) => f.status === "open").map((f: any) => f.id));
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
            : f.status === "open" ? <span className="flex flex-wrap items-center gap-1"><TicketButton kind="asm_finding" id={f.id} tickets={tickets[f.id]} />{can("risk.accept") && <Button size="sm" variant="ghost" onClick={() => setExc({ id: f.id, label: `${f.entity}: ${f.baseline}`, reason: "", until: null })}><ShieldOff /> Exception</Button>}</span> : null },
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


const PRIORITY_TONE: Record<string, "critical" | "serious" | "warning" | "outline"> = { P1: "critical", P2: "serious", P3: "warning", P4: "outline" };

/** Open vulnerabilities in fix order: known exploited (CISA KEV) first, then likely to be exploited (EPSS), then severity. */
function Vulnerabilities() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [priority, setPriority] = useUrlFilter("priority");
  const [kev, setKev] = useUrlFilter("kev");
  const [overdue, setOverdue] = useUrlFilter("overdue");
  const q = new URLSearchParams({ ...(priority ? { priority } : {}), ...(kev ? { kev: "true" } : {}), ...(overdue ? { overdue: "true" } : {}) });
  const { data } = useApi<any>(`/asm/vulnerabilities?${q}`);
  const pol = useApi<any>("/asm/vuln-policy");
  const [edit, setEdit] = useState<any>(null);
  const refresh = useAction(() => api<any>("/asm/vuln-intel/refresh", { method: "POST" }), { success: (r: any) => `Feeds updated: ${r.kev ?? 0} KEV entries, ${r.epss ?? 0} EPSS scores; ${r.prioritised} vulnerabilities re-prioritised.`, invalidate: ["/asm", "/dashboard"] });
  const save = useAction(() => api("/asm/vuln-policy", { method: "PUT", body: edit }), { success: "Prioritisation settings saved.", invalidate: ["/asm", "/dashboard"], onSuccess: () => setEdit(null) });
  const tickets = useTickets("vulnerability", (data?.items ?? []).map((v: any) => v.id));
  if (!data || !pol.data) return <Skeleton className="h-64" />;
  const s = data.summary;
  const p = pol.data;
  const labels: Record<string, string> = p.priority_labels;
  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Known exploited (CISA KEV)" value={s.known_exploited} tone={s.known_exploited ? "critical" : "good"} icon={Flame} />
        <Stat label="Past fix-by date" value={s.overdue} tone={s.overdue ? "warning" : "good"} />
        <Stat label="Likely to be exploited (P2)" value={s.by_priority.P2} hint={`EPSS ≥ ${Math.round(p.epss_threshold * 100)}% or a public exploit`} />
        <Stat label="Other open" value={s.by_priority.P3 + s.by_priority.P4} hint="Critical/high, then medium/low" />
      </div>
      <DataTable rows={data.items} rowKey={(v: any) => v.id} search={(v: any) => `${v.device} ${v.cve ?? ""} ${v.title}`}
        empty="No open vulnerabilities match. Connect a vulnerability scanner or EDR under Integrations to see them here."
        toolbar={<>
          <div className="w-52"><Select value={priority} onChange={setPriority} allowEmpty emptyLabel="Any priority" placeholder="Priority" ariaLabel="Priority" options={["P1", "P2", "P3", "P4"].map((k) => ({ value: k, label: `${k}: ${labels[k]}` }))} /></div>
          <Switch checked={!!kev} onChange={(v) => setKev(v ? "1" : null)} label="Known exploited only" />
          <Switch checked={!!overdue} onChange={(v) => setOverdue(v ? "1" : null)} label="Past fix-by date" />
        </>}
        columns={[
          { key: "p", header: "Priority", sort: (v: any) => v.priority, className: "w-40", cell: (v: any) => (
            <div className="space-y-1"><Badge tone={PRIORITY_TONE[v.priority] ?? "outline"} title={labels[v.priority]}>{v.priority} · {labels[v.priority]}</Badge>
              {v.ransomware && <div className="text-xs text-critical">Used by ransomware</div>}</div>) },
          { key: "v", header: "Vulnerability", sort: (v: any) => v.title, cell: (v: any) => (
            <div><div className="font-medium">{v.title}</div><div className="text-xs text-muted-foreground">{v.cve ?? "No CVE"}{v.cvss != null ? ` · CVSS ${v.cvss}` : ""}{v.epss != null ? ` · EPSS ${(v.epss * 100).toFixed(v.epss < 0.01 ? 2 : 0)}%` : ""}{v.exploitable ? " · public exploit" : ""}</div></div>) },
          { key: "s", header: "Severity", cell: (v: any) => <Sev s={v.severity} />, sort: (v: any) => ["critical", "high", "medium", "low"].indexOf(v.severity) },
          { key: "d", header: "Device", sort: (v: any) => v.device, cell: (v: any) => (
            <div><Link to={`/attack-surface?tab=devices&device=${v.device_id}`} className="font-medium hover:underline">{v.device}</Link>
              <div className="text-xs text-muted-foreground">{v.owner_user_id ? name(v.owner_user_id) : "No owner"}</div></div>) },
          { key: "f", header: "Fix by", sort: (v: any) => v.fix_by, cell: (v: any) => (
            <div className={v.overdue ? "font-medium text-critical" : undefined}>{fmtDate(v.fix_by)}
              <div className="text-xs font-normal text-muted-foreground">{v.days_left == null ? "" : v.overdue ? `${-v.days_left} day(s) late` : `${v.days_left} day(s) left`}</div></div>) },
          { key: "t", header: "Ticket", cell: (v: any) => <TicketButton kind="vulnerability" id={v.id} tickets={tickets[v.id]} /> },
        ]} />
      <Card>
        <CardHeader title="How priorities and deadlines are set"
          description="CISA's Known Exploited Vulnerabilities catalogue and FIRST's EPSS scores are downloaded once a day as whole files, so no outside service learns which vulnerabilities you have."
          action={can("integration.manage") && <div className="flex gap-2">
            <Button size="sm" variant="outline" loading={refresh.isPending} onClick={() => refresh.mutate(undefined)}><RefreshCw /> Update feeds now</Button>
            <Button size="sm" variant="outline" onClick={() => setEdit({ kev_enabled: p.kev_enabled, epss_enabled: p.epss_enabled, epss_threshold: p.epss_threshold, sla_critical: p.sla_critical, sla_high: p.sla_high, sla_medium: p.sla_medium, sla_low: p.sla_low, sla_kev: p.sla_kev })}>Change</Button>
          </div>} />
        <CardBody className="grid gap-5 md:grid-cols-2">
          <ul className="space-y-1 text-sm">
            {["P1", "P2", "P3", "P4"].map((k) => <li key={k}><Badge tone={PRIORITY_TONE[k]}>{k}</Badge> {labels[k]}{k === "P1" ? ": the CVE is on the KEV catalogue" : k === "P2" ? `: EPSS at or above ${Math.round(p.epss_threshold * 100)}%, or a public exploit for a critical/high one` : ""}</li>)}
          </ul>
          <KeyValue items={[
            ["Fix within", `critical ${p.sla_critical} · high ${p.sla_high} · medium ${p.sla_medium} · low ${p.sla_low} days`],
            ["Known exploited", `${p.sla_kev} days from first seen or KEV listing (if shorter)`],
            ["CISA KEV", p.kev_enabled ? (p.kev_refreshed_at ? `Updated ${fmtDate(p.kev_refreshed_at, true)}` : "Not downloaded yet") : "Off"],
            ["EPSS", p.epss_enabled ? (p.epss_score_date ? `Scores of ${fmtDate(p.epss_score_date)}` : "Not downloaded yet") : "Off"],
          ]} />
          {p.last_error && <p role="alert" className="text-sm text-critical md:col-span-2">Last update failed: {p.last_error}</p>}
        </CardBody>
      </Card>
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title="Vulnerability prioritisation" description="Deadlines count from the day a tool first reported the vulnerability."
        footer={<Button loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
        {edit && <div className="space-y-4">
          <Switch checked={edit.kev_enabled} onChange={(v) => setEdit({ ...edit, kev_enabled: v })} label="Use CISA Known Exploited Vulnerabilities (www.cisa.gov)" />
          <Switch checked={edit.epss_enabled} onChange={(v) => setEdit({ ...edit, epss_enabled: v })} label="Use FIRST EPSS scores (epss.empiricalsecurity.com)" />
          <Field label="EPSS threshold for P2 (%)" hint="Probability of exploitation in the next 30 days."><Input type="number" min={1} max={100} value={Math.round(edit.epss_threshold * 100)} onChange={(e) => setEdit({ ...edit, epss_threshold: Math.min(100, Math.max(1, Number(e.target.value) || 10)) / 100 })} /></Field>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            {([["sla_critical", "Critical"], ["sla_high", "High"], ["sla_medium", "Medium"], ["sla_low", "Low"], ["sla_kev", "Known exploited"]] as const).map(([k, l]) => (
              <Field key={k} label={`${l} (days)`}><Input type="number" min={1} max={730} value={edit[k]} onChange={(e) => setEdit({ ...edit, [k]: Math.min(730, Math.max(1, Number(e.target.value) || 1)) })} /></Field>
            ))}
          </div>
        </div>}
      </Dialog>
    </div>
  );
}

const ISSUE_TONE: Record<string, "critical" | "serious" | "warning" | "outline"> = { critical: "critical", high: "serious", medium: "warning", low: "outline" };

function Issues({ items }: { items: any[] }) {
  if (!items.length) return <span className="text-xs text-muted-foreground">No issues</span>;
  return <ul className="space-y-1">{items.map((i) => <li key={i.code} className="flex items-start gap-2 text-sm"><Badge tone={ISSUE_TONE[i.severity] ?? "outline"}>{titleCase(i.severity)}</Badge><span>{i.title}</span></li>)}</ul>;
}

/** Domains the organisation has proved it owns: email security records, and hosts found in certificate logs and DNS. */
function External() {
  const { can } = useAuth();
  const { data } = useApi<any>("/asm/external");
  const [name, setName] = useState("");
  const [host, setHost] = useState<{ id: number; value: string } | null>(null);
  const inv = ["/asm", "/dashboard"];
  const add = useAction(() => api("/asm/external/domains", { body: { name } }), { success: "Domain added. Publish the TXT record, then verify.", invalidate: inv, onSuccess: () => setName("") });
  const verify = useAction((id: number) => api(`/asm/external/domains/${id}/verify`, { method: "POST" }), { success: "Ownership verified.", invalidate: inv });
  const scan = useAction((id: number) => api<any>(`/asm/external/domains/${id}/scan`, { method: "POST" }), { success: (r: any) => `Checked ${r.hosts} host(s): ${r.issues} issue(s).`, invalidate: inv });
  const remove = useAction((id: number) => api(`/asm/external/domains/${id}`, { method: "DELETE" }), { success: "Domain removed.", invalidate: inv });
  const addHost = useAction(() => api(`/asm/external/domains/${host!.id}/hosts`, { body: { host: host!.value } }), { success: "Host added; it's checked on the next scan.", invalidate: inv, onSuccess: () => setHost(null) });
  if (!data) return <Skeleton className="h-64" />;
  const s = data.summary;
  const manage = can("integration.manage");
  return (
    <div className="space-y-5">
      <p className="max-w-3xl text-sm text-muted-foreground">Only domains you prove you own are checked, and only the way a browser or mail server would see them: certificate transparency logs, public DNS, and HTTPS. No port scanning. Checks run daily.</p>
      <div className="grid gap-3 sm:grid-cols-4">
        <Stat label="Critical" value={s.critical} tone={s.critical ? "critical" : "good"} />
        <Stat label="High" value={s.high} tone={s.high ? "warning" : "good"} />
        <Stat label="Medium" value={s.medium} />
        <Stat label="Low" value={s.low} />
      </div>
      {manage && (
        <Card><CardBody className="flex flex-wrap items-end gap-3">
          <div className="w-72"><Field label="Add a domain you own"><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="example.com" /></Field></div>
          <Button disabled={!name.trim()} loading={add.isPending} onClick={() => add.mutate(undefined)}><Plus /> Add domain</Button>
        </CardBody></Card>
      )}
      {data.domains.length === 0 && <Empty icon={Globe2} title="No domains yet">Add the domains your organisation uses for its website and email.</Empty>}
      {data.domains.map((d: any) => (
        <Card key={d.id}>
          <CardHeader title={<span className="flex items-center gap-2">{d.name}{d.verified ? <Badge tone="good"><CheckCircle2 className="h-3 w-3" />Verified</Badge> : <Badge tone="warning">Not verified</Badge>}</span>}
            description={d.last_scan_at ? `Last checked ${fmtDate(d.last_scan_at, true)} · ${d.hosts} host(s)` : d.verified ? "Not checked yet" : "Publish the TXT record below, then verify."}
            action={manage && <div className="flex flex-wrap gap-2">
              {d.verified ? <Button size="sm" variant="outline" loading={scan.isPending && scan.variables === d.id} onClick={() => scan.mutate(d.id)}><RefreshCw /> Check now</Button>
                : <Button size="sm" loading={verify.isPending && verify.variables === d.id} onClick={() => verify.mutate(d.id)}>Verify</Button>}
              {d.verified && <Button size="sm" variant="ghost" onClick={() => setHost({ id: d.id, value: "" })}><Plus /> Host</Button>}
              <Button size="sm" variant="ghost" aria-label={`Remove ${d.name}`} onClick={() => { if (confirm(`Remove ${d.name} and its results?`)) remove.mutate(d.id); }}><Trash2 /></Button>
            </div>} />
          <CardBody className="space-y-4">
            {d.scan_error && <p role="alert" className="text-sm text-critical">{d.scan_error}</p>}
            {!d.verified && d.verification && (
              <div className="rounded-md border bg-muted/40 p-3 text-sm">
                <p className="mb-2">Add this TXT record at your DNS provider. Keep it in place: Keystone checks it before every scan.</p>
                <KeyValue items={[["Name", <code key="n">{d.verification.name}</code>], ["Type", "TXT"], ["Value", <span key="v" className="flex items-center gap-2"><code className="break-all">{d.verification.value}</code><CopyButton text={d.verification.value} /></span>]]} />
              </div>
            )}
            {d.verified && d.last_scan_at && (
              <div className="grid gap-4 md:grid-cols-2">
                <div><p className="mb-2 text-sm font-medium">Email and certificates</p>
                  <KeyValue items={[["SPF", d.email.spf ?? "None"], ["DMARC", d.email.dmarc_policy ? `p=${d.email.dmarc_policy}` : "None"], ["CAA", d.email.caa?.length ? d.email.caa.join(", ") : "None"]]} /></div>
                <div><p className="mb-2 text-sm font-medium">Domain issues</p><Issues items={d.issues} /></div>
              </div>
            )}
          </CardBody>
        </Card>
      ))}
      {data.hosts.length > 0 && (
        <DataTable rows={data.hosts} rowKey={(h: any) => h.id} search={(h: any) => h.host}
          columns={[
            { key: "w", header: "Worst", sort: (h: any) => ["critical", "high", "medium", "low"].indexOf(h.worst ?? "") + (h.worst ? 0 : 9), className: "w-24", cell: (h: any) => h.worst ? <Badge tone={ISSUE_TONE[h.worst]}>{titleCase(h.worst)}</Badge> : <span className="text-xs text-muted-foreground">None</span> },
            { key: "h", header: "Host", sort: (h: any) => h.host, cell: (h: any) => <div><div className="font-medium">{h.host}</div><div className="text-xs text-muted-foreground">{h.source === "ct" ? "Certificate logs" : h.source === "manual" ? "Added by hand" : "DNS"} · since {fmtDate(h.first_seen)}</div></div> },
            { key: "f", header: "Seen", cell: (h: any) => <div className="text-xs">{h.facts.web === "https" ? `HTTPS${h.facts.tls_version ? ` (${h.facts.tls_version})` : ""}${h.facts.cert_expires ? `, certificate until ${fmtDate(h.facts.cert_expires)}` : ""}` : h.facts.web === "no address" ? "Doesn't resolve" : h.facts.web === "no https" ? "No HTTPS service" : "Not checked"}{h.facts.cname ? <div className="text-muted-foreground">CNAME {h.facts.cname}</div> : null}</div> },
            { key: "i", header: "Issues", cell: (h: any) => <Issues items={h.issues} /> },
          ]} />
      )}
      <Dialog open={!!host} onOpenChange={(o) => !o && setHost(null)} title="Add a host" description="For names certificate logs don't show, such as hosts covered by a wildcard certificate. Must be part of the domain."
        footer={<Button disabled={!host?.value.trim()} loading={addHost.isPending} onClick={() => addHost.mutate(undefined)}>Add</Button>}>
        {host && <Field label="Host name"><Input value={host.value} onChange={(e) => setHost({ ...host, value: e.target.value })} placeholder="intranet.example.com" /></Field>}
      </Dialog>
    </div>
  );
}
