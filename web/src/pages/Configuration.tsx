import { useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { AlertTriangle, BookPlus, Boxes, Copy, Download, FileUp, KeyRound, Pencil, Plus, Radar, RotateCcw, ServerCog, ShieldOff, Trash2, Upload } from "lucide-react";
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
import { Comments } from "@/components/Comments";
import { CopyButton } from "@/components/CopyButton";
import { allowedTypes, describeExpected, expectedFromInput, expectedToInput, parseList, parseTags, resultLabel, type Probe, type Setting } from "@/lib/configcheck";

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
  const a = t.agent ?? {};
  const live = t.state !== "revoked";
  return (
    <span className="inline-flex flex-wrap gap-1"><Badge tone={tone}>{label}</Badge>
      {t.stale && live && t.state !== "waiting" && <Badge tone="warning">Results out of date</Badge>}
      {a.silent && live && <Badge tone="warning">Quiet</Badge>}
      {a.integrity === "modified" && live && <Badge tone="critical">Modified agent</Badge>}
      {a.outdated && live && <Badge tone="outline">Agent {t.agent_version}: update to {a.latest_version}</Badge>}
    </span>
  );
}

const INTEGRITY: Record<string, string> = {
  ok: "A script Keystone handed out",
  modified: "Not a script Keystone handed out: it was changed on the host",
  unknown: "Not reported (agents before 1.2)",
};

function Tags({ tags }: { tags?: string[] | null }) {
  if (!tags?.length) return null;
  return <span className="inline-flex flex-wrap gap-1">{tags.map((t) => <Badge key={t} tone="outline">{t}</Badge>)}</span>;
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
      <PageHeader icon={ServerCog} title="Configuration" description="Set the required settings for Windows, macOS and Linux hosts and for firewalls, add your own checks, and scope baselines to groups of hosts. Agents on the hosts report their settings (they never change anything); firewall configurations are uploaded. Anything not reported counts as unknown, never as passing."
        actions={<a href={downloadUrl("/config/report.xlsx")}><Button variant="outline"><Download /> Compliance report</Button></a>} />
      <Tabs value={tab} onValueChange={go} tabs={[
        { value: "overview", label: "Overview", content: <Overview data={data} catalogue={catalogue} go={go} /> },
        { value: "targets", label: "Hosts and firewalls", content: <Targets catalogue={catalogue} /> },
        { value: "baselines", label: "Baselines", content: <Baselines catalogue={catalogue} /> },
        { value: "custom", label: "Custom checks", content: <CustomChecks catalogue={catalogue} /> },
        { value: "coverage", label: "Coverage", content: <Coverage /> },
        { value: "software", label: "Software", content: <Software /> },
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
        Create a baseline for each platform (the recommended settings are filled in for you), then install the report-only agent on Windows, macOS and Linux hosts, or upload configuration exports from FortiGate, PAN-OS, Cisco and pfSense/OPNsense firewalls. Add your own checks under Custom checks.
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
          <CardHeader title="By platform" description="Targets that meet every baseline that applies to them." />
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
  const [tag, setTag] = useState<string | null>(null);
  const label = (k: string) => catalogue.platforms.find((p: any) => p.key === k)?.label ?? k;
  const open = params.get("target");
  const allTags = [...new Set((data ?? []).flatMap((t) => t.tags ?? []))].sort();
  const rows = (data ?? []).filter((t) => (!platform || t.platform === platform) && (!tag || (t.tags ?? []).includes(tag)));
  return (
    <>
      <DataTable rows={rows} rowKey={(t: any) => t.id} onRowClick={(t: any) => setParams({ tab: "targets", target: String(t.id) })} rowLabel={(t: any) => t.name}
        search={(t: any) => `${t.name} ${t.hostname ?? ""} ${t.os_name ?? ""} ${(t.tags ?? []).join(" ")}`} empty="No hosts or firewalls yet."
        toolbar={<div className="flex flex-wrap gap-2">
          <Select ariaLabel="Platform" value={platform} onChange={setPlatform} allowEmpty emptyLabel="All platforms" options={catalogue.platforms.map((p: any) => ({ value: p.key, label: p.label }))} className="w-48" />
          {allTags.length > 0 && <Select ariaLabel="Tag" value={tag} onChange={setTag} allowEmpty emptyLabel="All tags" options={allTags.map((t) => ({ value: t, label: t }))} className="w-40" />}
        </div>}
        columns={[
          { key: "n", header: "Name", mobile: "heading", cell: (t: any) => <span><span className="font-medium">{t.name}</span>{t.hostname && t.hostname !== t.name && <span className="block text-xs text-muted-foreground">{t.hostname}</span>}<span className="mt-1 block"><Tags tags={t.tags} /></span></span>, sort: (t: any) => t.name },
          { key: "p", header: "Platform", cell: (t: any) => <span>{label(t.platform)}<span className="block text-xs text-muted-foreground">{t.kind === "agent" ? "Agent" : "Uploaded configuration"}</span></span>, sort: (t: any) => t.platform },
          { key: "b", header: "Baselines", cell: (t: any) => (t.baselines?.length ? t.baselines.map((b: any) => b.name).join(", ") : <span className="text-muted-foreground">None</span>) },
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
  const { data: assets } = useApi<any[]>("/assets");
  const { can } = useAuth();
  const [except, setExcept] = useState<any>(null);
  const [tagText, setTagText] = useState<string | null>(null);
  const patch = useAction((v: any) => api(`/config/targets/${id}`, { method: "PATCH", body: v }), { success: "Saved.", invalidate: INV, onSuccess: () => setTagText(null) });
  const revoke = useAction(() => api(`/config/targets/${id}/revoke`, { method: "POST" }), { success: "Agent token revoked.", invalidate: INV });
  const remove = useAction(() => api(`/config/targets/${id}`, { method: "DELETE" }), { success: "Removed.", invalidate: INV, onSuccess: onClose });
  const unexcept = useAction((fid: number) => api(`/config/findings/${fid}/exception/revoke`, { method: "POST" }), { success: "Exception withdrawn.", invalidate: INV });
  const label = catalogue.platforms.find((p: any) => p.key === t?.platform)?.label;
  const manage = can("integration.manage");
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={t?.name ?? "…"} subtitle={t && `${label} · ${t.kind === "agent" ? "agent" : "uploaded configuration"}`}
      actions={t && <>
        <a href={downloadUrl(`/config/report.xlsx?target_id=${t.id}`)}><Button size="sm" variant="outline"><Download /> Report</Button></a>
        {manage && t.kind === "agent" && !t.revoked_at && <Button size="sm" variant="outline" loading={revoke.isPending} onClick={() => window.confirm(`Revoke ${t.name}'s agent token? It will stop reporting.`) && revoke.mutate(undefined)}><ShieldOff /> Revoke</Button>}
        {manage && <Button size="sm" variant="outline" loading={remove.isPending} onClick={() => window.confirm(`Remove ${t.name} and its results?`) && remove.mutate(undefined)}><Trash2 /> Remove</Button>}
      </>}>
      {!t ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2"><StateBadge t={t} />{t.score !== null && <span className="text-sm text-muted-foreground">{t.score}% of known results pass</span>}</div>
          <KeyValue items={[
            ["Host name", t.hostname ?? "—"],
            ["Operating system", [t.os_name, t.os_version].filter(Boolean).join(" ") || "—"],
            ...(t.kind === "agent" ? [
              ["Agent", `${t.agent_version ?? "?"}${t.agent?.outdated ? ` (${t.agent.latest_version} available)` : ""} · enrolled ${fmtDate(t.enrolled_at, true)}${t.last_ip ? ` from ${t.last_ip}` : ""}${t.custom_checks === "disabled" ? " · custom checks off" : ""}`],
              ["Agent script", INTEGRITY[t.agent?.integrity ?? "unknown"]],
              ["Last heard from", t.agent?.last_contact ? `${fmtDate(t.agent.last_contact, true)}${t.agent.checks_in ? " (checks in every hour)" : ""}` : "Not yet"],
            ] as [string, string][] : []),
            ...(t.kind === "firewall" ? [["File", <span key="f">{t.source_filename}<span className="block break-all font-mono text-xs text-muted-foreground">SHA-256 {t.source_sha256}</span></span>] as [string, any]] : []),
            ["Last report", t.facts_at ? fmtDate(t.facts_at, true) : "Not yet"],
            ["Baselines", t.baselines.length ? t.baselines.map((b: any) => b.name).join(", ") : "None apply"],
            ["Pinned baseline", manage ? (
              <Select key="b" ariaLabel="Pinned baseline" value={t.baseline_id && baselines?.some((b) => b.id === t.baseline_id && !b.is_default) ? String(t.baseline_id) : null} allowEmpty emptyLabel="Platform default"
                onChange={(v) => patch.mutate(v ? { baseline_id: Number(v) } : { clear_baseline: true })}
                options={(baselines ?? []).filter((b) => b.platform === t.platform && !b.scope).map((b) => ({ value: String(b.id), label: b.name + (b.is_default ? " (default)" : "") }))} />
            ) : "—"],
            ["Tags", manage ? (
              <div key="t" className="flex gap-2">
                <Input aria-label="Tags" value={tagText ?? (t.tags ?? []).join(", ")} onChange={(e) => setTagText(e.target.value)} placeholder="e.g. web, dmz" />
                {tagText !== null && <Button size="sm" loading={patch.isPending} onClick={() => patch.mutate({ tags: parseTags(tagText) })}>Save</Button>}
              </div>
            ) : <Tags key="t" tags={t.tags} />],
            ["Asset", manage ? (
              <div key="a" className="space-y-1">
                <Select ariaLabel="Asset" value={t.asset ? String(t.asset.id) : null} allowEmpty emptyLabel="Not linked"
                  onChange={(v) => patch.mutate(v ? { asset_id: Number(v) } : { clear_asset: true })}
                  options={(assets ?? []).map((a) => ({ value: String(a.id), label: a.name }))} />
                {!t.asset && t.asset_suggestions.length > 0 && <div className="text-xs text-muted-foreground">Suggested: {t.asset_suggestions.map((a: any) => <Button key={a.id} size="sm" variant="ghost" onClick={() => patch.mutate({ asset_id: a.id })}>{a.name}</Button>)}</div>}
              </div>
            ) : t.asset?.name ?? "Not linked"],
          ]} />
          {t.revoked_at && <p className="text-sm text-muted-foreground">The agent token was revoked on {fmtDate(t.revoked_at, true)}. These are its last results.</p>}
          {t.agent?.integrity === "modified" && !t.revoked_at && <div className="flex items-start gap-2 rounded-lg border border-critical/30 bg-critical/5 px-4 py-3 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-critical" aria-hidden />
            <div>The agent script on this host isn't one Keystone handed out. Check who changed it, then reinstall it from the Agents tab. Until then, treat this host's results with care: a changed agent can report anything.</div></div>}
          <Section title="Results">
            {t.results.length === 0 ? <p className="text-sm text-muted-foreground">{t.baselines.length ? "Waiting for the first report." : "No baseline applies. Create one for this platform, scope one to this host's tags, or pin one above."}</p> : (
              <ul className="divide-y rounded-lg border">
                {t.results.map((r: any) => (
                  <li key={r.id} className="space-y-1 px-4 py-3 text-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium">{r.title}{r.custom && <Badge tone="primary" className="ml-2">Custom</Badge>}</span>
                      <span className="flex items-center gap-1.5"><Sev s={r.severity} /><Result s={r.status} /></span>
                    </div>
                    <div className="text-xs text-muted-foreground">Required: {r.rule} · Reported: <Value v={r.actual} /> · {r.baseline}{r.controls.length ? ` · ${r.controls.join(", ")}` : ""}</div>
                    {(r.status === "unknown" || r.status === "na") && r.detail && <div className="text-xs">{r.detail}</div>}
                    {r.status === "fail" && r.remediation && <div className="rounded-md bg-muted px-3 py-2 text-xs"><span className="font-medium">How to fix: </span>{r.remediation}</div>}
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
          {t.kind === "agent" && <InstalledSoftware t={t} />}
          <Section title="Discussion">
            <Comments kind="config_target" id={t.id} />
          </Section>
          <Section title="History">
            {t.history.length === 0 ? <p className="text-sm text-muted-foreground">No reports yet.</p> : (
              <ul className="space-y-2 text-sm">
                {t.history.slice(0, 30).map((h: any) => (
                  <li key={h.id} className="rounded-md border px-3 py-2">
                    <div className="flex flex-wrap justify-between gap-2"><span>{fmtDate(h.at, true)} · {h.source === "agent" ? "agent report" : h.source === "upload" ? "upload" : "re-checked"}</span>
                      <span className="text-xs text-muted-foreground">{h.counts.fail ?? 0} failing · {h.counts.unknown ?? 0} unknown · {h.counts.pass ?? 0} passing</span></div>
                    {h.changes.length > 0 && <ul className="mt-1 text-xs">{h.changes.map((c: any, i: number) => <li key={`${c.key}-${i}`}>{titleForKey(catalogue, t.platform, c.key)}: {resultLabel(c.from)} → {resultLabel(c.to)}</li>)}</ul>}
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </div>
      )}
      {except && <ExceptionDialog title={except.title} path={`/config/findings/${except.id}/exception`} onClose={() => setExcept(null)} />}
    </Sheet>
  );
}

function titleForKey(catalogue: any, platform: string, key: string): string {
  return catalogue.platforms.find((p: any) => p.key === platform)?.settings.find((s: Setting) => s.key === key)?.title ?? key;
}

function ExceptionDialog({ title, path, onClose, description }: { title: string; path: string; onClose: () => void; description?: string }) {
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState<string | null>(null);
  const save = useAction(() => api<any>(path, { method: "POST", body: { reason, until } }), {
    success: (r: any) => (typeof r.excepted === "number" ? `Exception granted on ${r.excepted} target(s).` : "Exception granted."), invalidate: INV, onSuccess: onClose,
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Exception: ${title}`} description={description ?? "The result stays visible as excepted until the end date, then fails again."}
      footer={<Button disabled={!reason.trim() || !until} loading={save.isPending} onClick={() => save.mutate(undefined)}>Grant exception</Button>}>
      <div className="space-y-4">
        <Field label="Reason" required><Textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why these hosts may differ, and what compensates for it" /></Field>
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
  const file = useRef<HTMLInputElement>(null);
  const label = (k: string) => catalogue.platforms.find((p: any) => p.key === k)?.label ?? k;
  const importJson = useAction(async (f: File) => api<any>("/config/baselines/import", { body: JSON.parse(await f.text()) }), {
    success: (r: any) => `Imported “${r.baseline.name}”.${r.notes.length ? " " + r.notes.join(" ") : ""}`, invalidate: INV, onSuccess: (r: any) => setOpen(r.baseline.id),
  });
  const scopeText = (b: any) => {
    if (b.is_default && !b.scope) return "Every target of the platform without a pinned baseline";
    const parts = [...(b.scope?.tags ?? []).map((t: string) => `tag ${t}`), ...(b.scope?.names ?? []).map((n: string) => `names ${n}`)];
    return parts.length ? `${b.is_default ? "Default, and " : ""}${parts.join(" or ")}` : "Targets pinned to it";
  };
  return (
    <>
      <DataTable rows={data ?? []} rowKey={(b: any) => b.id} onRowClick={(b: any) => setOpen(b.id)} rowLabel={(b: any) => b.name} empty="No baselines yet."
        toolbar={can("integration.manage") && <div className="flex flex-wrap gap-2">
          <Button onClick={() => setCreating(true)}><Plus /> New baseline</Button>
          <Button variant="outline" loading={importJson.isPending} onClick={() => file.current?.click()}><FileUp /> Import</Button>
          <input ref={file} type="file" accept=".json,application/json" className="hidden" aria-label="Baseline file to import"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) importJson.mutate(f); e.target.value = ""; }} />
        </div>}
        columns={[
          { key: "n", header: "Name", mobile: "heading", cell: (b: any) => <span className="font-medium">{b.name}</span>, sort: (b: any) => b.name },
          { key: "p", header: "Platform", cell: (b: any) => label(b.platform), sort: (b: any) => b.platform },
          { key: "r", header: "Rules", cell: (b: any) => `${b.enabled_rules} of ${b.rules} on` },
          { key: "d", header: "Applies to", cell: (b: any) => <span className="text-xs">{scopeText(b)}</span> },
          { key: "e", header: "Status", cell: (b: any) => (b.enabled ? <Badge tone="good">On</Badge> : <Badge tone="outline">Off</Badge>) },
        ]} />
      {creating && <NewBaseline catalogue={catalogue} onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); setOpen(id); }} />}
      {open && <BaselineEditor id={open} catalogue={catalogue} onClose={() => setOpen(null)} onOpen={setOpen} />}
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

function BaselineEditor({ id, catalogue, onClose, onOpen }: { id: number; catalogue: any; onClose: () => void; onOpen: (id: number) => void }) {
  const { data: b } = useApi<any>(`/config/baselines/${id}`);
  const { can } = useAuth();
  const edit = can("integration.manage");
  const [adding, setAdding] = useState<string | null>(null);
  const [editing, setEditing] = useState<any>(null);
  const [scope, setScope] = useState<{ tags: string; names: string } | null>(null);
  const [excepting, setExcepting] = useState<any>(null);
  const patch = useAction((v: any) => api(`/config/baselines/${id}`, { method: "PATCH", body: v }), { success: "Saved.", invalidate: INV, onSuccess: () => setScope(null) });
  const remove = useAction(() => api(`/config/baselines/${id}`, { method: "DELETE" }), { success: "Baseline deleted.", invalidate: INV, onSuccess: onClose });
  const clone = useAction(() => api<any>(`/config/baselines/${id}/clone`, { body: {} }), { success: "Copied.", invalidate: INV, onSuccess: (r) => onOpen(r.id) });
  const toggle = useAction((r: any) => api(`/config/rules/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } }), { invalidate: INV });
  const reset = useAction((r: any) => api(`/config/rules/${r.id}/reset`, { method: "POST" }), { success: "Back to the recommended value.", invalidate: INV });
  const drop = useAction((r: any) => api(`/config/rules/${r.id}`, { method: "DELETE" }), { success: "Rule removed.", invalidate: INV });
  const settings: Setting[] = useMemo(() => catalogue.platforms.find((p: any) => p.key === b?.platform)?.settings ?? [], [catalogue, b]);
  const unused = settings.filter((s) => !b?.rules.some((r: any) => r.key === s.key));
  const scopeForm = scope ?? { tags: (b?.scope?.tags ?? []).join(", "), names: (b?.scope?.names ?? []).join(", ") };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} extraWide title={b?.name ?? "…"} description={b && catalogue.platforms.find((p: any) => p.key === b.platform)?.label}
      footer={b && <div className="flex flex-wrap gap-2">
        <a href={downloadUrl(`/config/baselines/${id}/export`)}><Button variant="outline"><Download /> Export</Button></a>
        <a href={downloadUrl(`/config/report.xlsx?baseline_id=${id}`)}><Button variant="outline"><Download /> Report</Button></a>
        {edit && <Button variant="outline" loading={clone.isPending} onClick={() => clone.mutate(undefined)}><Copy /> Copy</Button>}
        {edit && <Button variant="outline" loading={remove.isPending} onClick={() => window.confirm(`Delete the baseline “${b.name}”? Its results are removed.`) && remove.mutate(undefined)}><Trash2 /> Delete</Button>}
      </div>}>
      {!b ? <Skeleton className="h-64" /> : (
        <div className="space-y-5">
          {edit && (
            <div className="flex flex-wrap gap-6">
              <Switch checked={b.enabled} onChange={(v) => patch.mutate({ enabled: v })} label="Baseline on" />
              <Switch checked={b.is_default} onChange={(v) => patch.mutate({ is_default: v })} label="Default for this platform" />
            </div>
          )}
          <Card>
            <CardHeader title="Also applies to" description="Targets with any of these tags, or whose name matches a pattern (* any characters, ? one), get this baseline as well as their default." />
            <CardBody className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
              <Field label="Tags"><Input disabled={!edit} value={scopeForm.tags} onChange={(e) => setScope({ ...scopeForm, tags: e.target.value })} placeholder="web, dmz" /></Field>
              <Field label="Host-name patterns"><Input disabled={!edit} value={scopeForm.names} onChange={(e) => setScope({ ...scopeForm, names: e.target.value })} placeholder="web-*, db-0?" /></Field>
              {edit && scope && <Button loading={patch.isPending} onClick={() => {
                const tags = parseTags(scope.tags);
                const names = parseList(scope.names);
                patch.mutate(tags.length || names.length ? { scope: { tags, names } } : { clear_scope: true });
              }}>Save scope</Button>}
            </CardBody>
          </Card>
          <DataTable rows={b.rules} rowKey={(r: any) => r.id} rowLabel={(r: any) => r.title} empty="No rules yet."
            toolbar={edit && unused.length > 0 && <Select ariaLabel="Add a rule" value={null} placeholder="Add a rule…" onChange={(v) => setAdding(v)} options={unused.map((s) => ({ value: s.key, label: (s.custom ? "Custom: " : "") + s.title }))} className="w-80" />}
            columns={[
              { key: "t", header: "Setting", mobile: "heading", cell: (r: any) => <span className={r.enabled ? "" : "text-muted-foreground line-through"}>{r.title}{r.custom && <Badge tone="primary" className="ml-2">Custom</Badge>}{r.applies_to_tags && <span className="mt-1 block text-xs text-muted-foreground">Only tags: {r.applies_to_tags.join(", ")}</span>}</span>, sort: (r: any) => r.title },
              { key: "r", header: "Required", cell: (r: any) => <span>{r.rule}{r.recommended && !r.is_recommended && <span className="block text-xs text-muted-foreground">Recommended: {r.recommended}</span>}</span> },
              { key: "s", header: "Severity", cell: (r: any) => <Sev s={r.severity} />, sort: (r: any) => ["critical", "high", "medium", "low"].indexOf(r.severity) },
              { key: "c", header: "Controls", cell: (r: any) => <span className="text-xs">{r.controls.join(", ") || "—"}</span> },
              ...(edit || can("risk.accept") ? [{ key: "a", header: "", cell: (r: any) => (
                <span className="flex flex-wrap justify-end gap-1">
                  {edit && <Button size="sm" variant="ghost" aria-label={`Edit ${r.title}`} onClick={() => setEditing(r)}><Pencil /></Button>}
                  {edit && r.recommended && !r.is_recommended && <Button size="sm" variant="ghost" aria-label={`Reset ${r.title} to recommended`} onClick={() => reset.mutate(r)}><RotateCcw /></Button>}
                  {edit && <Button size="sm" variant="ghost" onClick={() => toggle.mutate(r)}>{r.enabled ? "Turn off" : "Turn on"}</Button>}
                  {can("risk.accept") && <Button size="sm" variant="ghost" onClick={() => setExcepting(r)}>Exception</Button>}
                  {edit && <Button size="sm" variant="ghost" aria-label={`Remove ${r.title}`} onClick={() => drop.mutate(r)}><Trash2 /></Button>}
                </span>) }] : []),
            ]} />
        </div>
      )}
      {(adding || editing) && b && (
        <RuleDialog baselineId={id} setting={settings.find((s) => s.key === (editing?.key ?? adding))!} rule={editing} severities={catalogue.severities} operators={catalogue.operators}
          onClose={() => { setAdding(null); setEditing(null); }} />
      )}
      {excepting && <ExceptionDialog title={excepting.title} path={`/config/rules/${excepting.id}/exceptions`} onClose={() => setExcepting(null)}
        description="Grants an exception on every target where this rule currently fails. Each stays visible as excepted until the end date, then fails again." />}
    </Dialog>
  );
}

function RuleDialog({ baselineId, setting, rule, severities, operators, onClose }: { baselineId: number; setting: Setting; rule?: any; severities: string[]; operators: Record<string, string>; onClose: () => void }) {
  const rec = setting.recommended;
  const [op, setOp] = useState<string>(rule?.operator ?? rec?.operator ?? setting.operators[0]);
  const [value, setValue] = useState<string>(expectedToInput(rule ? rule.expected : rec?.expected));
  const [severity, setSeverity] = useState<string>(rule?.severity ?? rec?.severity ?? "medium");
  const [controls, setControls] = useState<string>((rule?.controls ?? rec?.controls ?? []).join(", "));
  const [tags, setTags] = useState<string>((rule?.applies_to_tags ?? []).join(", "));
  const [remediation, setRemediation] = useState<string>(rule?.remediation ?? "");
  const needsValue = !["is_true", "is_false", "empty"].includes(op);
  const body = { operator: op, expected: expectedFromInput(setting, op, value), severity, controls: controls.split(/[,\s]+/).filter(Boolean), applies_to_tags: parseTags(tags), remediation };
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
        <Field label="Only for tags" hint="Leave empty to check every target the baseline applies to."><Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="e.g. jump-host" /></Field>
        <Field label="How to fix" hint="Shown on failing results."><Textarea value={remediation} onChange={(e) => setRemediation(e.target.value)} /></Field>
        <p className="text-sm text-muted-foreground">Passes when the setting {describeExpected(operators, op, body.expected)}.{setting.requires ? " Not applicable when its prerequisite is off." : ""}</p>
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------- custom checks

function CustomChecks({ catalogue }: { catalogue: any }) {
  const { data } = useApi<any>("/config/custom-checks");
  const { can } = useAuth();
  const [editing, setEditing] = useState<any>(null);
  const [platform, setPlatform] = useState<string | null>(null);
  const addLib = useAction((key: string) => api(`/config/custom-checks/library/${key}`, { method: "POST" }), { success: "Added. Add it to a baseline as a rule.", invalidate: INV });
  const remove = useAction((c: any) => api(`/config/custom-checks/${c.id}`, { method: "DELETE" }), { success: "Custom check deleted.", invalidate: INV });
  if (!data) return <Skeleton className="h-64" />;
  const label = (k: string) => catalogue.platforms.find((p: any) => p.key === k)?.label ?? k;
  const probes: Probe[] = data.probes;
  const probeLabel = (k: string) => probes.find((p) => p.key === k)?.label ?? k;
  const manage = can("integration.manage");
  const lib = data.library.filter((e: any) => !platform || e.platform === platform);
  return (
    <div className="space-y-6">
      <p className="max-w-4xl text-sm text-muted-foreground">Custom checks read one more setting from your hosts or firewall exports, for example a registry value, a line in a configuration file, a service or a package. Agents fetch the definitions and read the values themselves; they never run commands, never read password or key files, and can be installed with custom checks turned off. Add a custom check to a baseline as a rule to compare its value.</p>
      <DataTable rows={data.checks} rowKey={(c: any) => c.id} rowLabel={(c: any) => c.title} onRowClick={manage ? (c: any) => setEditing(c) : undefined} empty="No custom checks yet. Start from the library below or create one."
        toolbar={manage && <Button onClick={() => setEditing({})}><Plus /> New custom check</Button>}
        columns={[
          { key: "t", header: "Check", mobile: "heading", cell: (c: any) => <span><span className="font-medium">{c.title}</span><span className="block font-mono text-xs text-muted-foreground">{c.key}</span></span>, sort: (c: any) => c.title },
          { key: "p", header: "Platform", cell: (c: any) => label(c.platform), sort: (c: any) => c.platform },
          { key: "r", header: "Reads", cell: (c: any) => <span className="text-xs">{probeLabel(c.probe)}: {Object.values(c.params).join(" · ")}</span> },
          { key: "u", header: "Used by", cell: (c: any) => <span className="text-xs">{c.used_by.join(", ") || "No baseline yet"}</span> },
          ...(manage ? [{ key: "a", header: "", cell: (c: any) => <Button size="sm" variant="ghost" aria-label={`Delete ${c.title}`} onClick={(e) => { e.stopPropagation(); if (window.confirm(`Delete “${c.title}”?`)) remove.mutate(c); }}><Trash2 /></Button> }] : []),
        ]} />
      <Card>
        <CardHeader title="Library" description="Checks written by Keystone, ready to add. Each comes with a suggested rule you can change."
          action={<Select ariaLabel="Library platform" value={platform} onChange={setPlatform} allowEmpty emptyLabel="All platforms" options={catalogue.platforms.map((p: any) => ({ value: p.key, label: p.label }))} className="w-48" />} />
        <CardBody className="p-0">
          <ul className="divide-y">
            {lib.map((e: any) => (
              <li key={`${e.platform}-${e.slug}`} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 text-sm">
                <span className="min-w-0 flex-1"><span className="font-medium">{e.title}</span> <span className="text-xs text-muted-foreground">· {label(e.platform)} · {probeLabel(e.probe)}</span><span className="block text-xs text-muted-foreground">{e.description}</span></span>
                {e.added ? <Badge tone="good">Added</Badge> : manage && <Button size="sm" variant="outline" loading={addLib.isPending && addLib.variables === e.slug} onClick={() => addLib.mutate(e.slug)}><BookPlus /> Add</Button>}
              </li>
            ))}
          </ul>
        </CardBody>
      </Card>
      {editing && <CustomCheckDialog check={editing} probes={probes} catalogue={catalogue} onClose={() => setEditing(null)} />}
    </div>
  );
}

function CustomCheckDialog({ check, probes, catalogue, onClose }: { check: any; probes: Probe[]; catalogue: any; onClose: () => void }) {
  const isNew = !check.id;
  const [platform, setPlatform] = useState<string>(check.platform ?? "linux");
  const [form, setForm] = useState({ slug: check.slug ?? "", title: check.title ?? "", description: check.description ?? "", remediation: check.remediation ?? "" });
  const [probeKey, setProbeKey] = useState<string>(check.probe ?? "");
  const [params, setParams] = useState<Record<string, string>>(check.params ?? {});
  const [valueType, setValueType] = useState<string>(check.value_type ?? "");
  const [def, setDef] = useState<string>(check.default_value === null || check.default_value === undefined ? "" : String(check.default_value));
  const available = probes.filter((p) => p.platforms.includes(platform));
  const probe = probes.find((p) => p.key === probeKey);
  const types = allowedTypes(probe, params);
  const type = types.includes(valueType) ? valueType : types[0] ?? "";
  const body: any = { title: form.title, description: form.description, remediation: form.remediation, probe: probeKey, params, value_type: type,
    default_value: probe?.default_allowed && type !== "bool" && def.trim() ? def.trim() : null };
  if (isNew) Object.assign(body, { platform, slug: form.slug });
  const save = useAction(() => (isNew ? api("/config/custom-checks", { body }) : api(`/config/custom-checks/${check.id}`, { method: "PATCH", body })),
    { success: "Custom check saved.", invalidate: INV, onSuccess: onClose });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} wide title={isNew ? "New custom check" : check.title}
      description={probe?.description}
      footer={<Button disabled={!form.title.trim() || !probeKey || !type || (isNew && !form.slug)} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Platform"><Select ariaLabel="Platform" disabled={!isNew} value={platform} onChange={(v) => { setPlatform(v ?? platform); setProbeKey(""); setParams({}); }} options={catalogue.platforms.map((p: any) => ({ value: p.key, label: p.label }))} /></Field>
          <Field label="Key" hint={isNew ? "Lower-case letters, digits and _; used in reports as custom.<key>." : "Can't change once created."}><Input disabled={!isNew} value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} placeholder="ssh_max_sessions" /></Field>
        </div>
        <Field label="Title" required><Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
        <Field label="What to read"><Select ariaLabel="Probe" value={probeKey || null} placeholder="Choose…" onChange={(v) => { setProbeKey(v ?? ""); setParams({}); }} options={available.map((p) => ({ value: p.key, label: p.label }))} /></Field>
        {probe && (
          <div className="grid gap-4 sm:grid-cols-2">
            {probe.params.map((p) => (
              <Field key={p.name} label={p.label} required={p.required} hint={p.hint || undefined}>
                {p.kind === "choice"
                  ? <Select ariaLabel={p.label} value={params[p.name] ?? null} placeholder="Choose…" onChange={(v) => setParams({ ...params, [p.name]: v ?? "" })} options={p.choices.map((c) => ({ value: c, label: titleCase(c.replace("_", " ")) }))} />
                  : <Input value={params[p.name] ?? ""} onChange={(e) => setParams({ ...params, [p.name]: e.target.value })} />}
              </Field>
            ))}
            {types.length > 1 && <Field label="Value is a"><Select ariaLabel="Value type" value={type} onChange={(v) => setValueType(v ?? type)} options={types.map((t) => ({ value: t, label: t === "int" ? "Number" : t === "str" ? "Text" : "Yes/no" }))} /></Field>}
            {probe.default_allowed && type !== "bool" && <Field label="When not set, use" hint="Optional. Without it, a missing value is unknown."><Input value={def} onChange={(e) => setDef(e.target.value)} /></Field>}
          </div>
        )}
        {probe?.reads_content && <p className="text-xs text-muted-foreground">Agents refuse to read password, key and home-directory files with this probe. Check such files' permissions with “File permissions or owner” instead.</p>}
        <Field label="Description"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <Field label="How to fix" hint="Shown on failing results."><Textarea value={form.remediation} onChange={(e) => setForm({ ...form, remediation: e.target.value })} /></Field>
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------- agents

const AGENT_PLATFORMS: { key: "windows" | "macos" | "linux"; title: string; about: string; install: string }[] = [
  { key: "windows", title: "Windows", about: "PowerShell 5.1 or later. Installs a scheduled task that runs as SYSTEM at startup and every hour.", install: "Install from an elevated PowerShell prompt in the download folder" },
  { key: "macos", title: "macOS", about: "macOS 12 or later, nothing to install first (sh and curl are built in). Installs a launchd service that runs every hour.", install: "Install with sudo in the download folder" },
  { key: "linux", title: "Linux", about: "Any distribution with sh and curl. Installs a systemd timer, or a cron job where there's no systemd, that runs every hour.", install: "Install as root in the download folder" },
];

function Agents() {
  const { data } = useApi<any>("/config/agent");
  const [limits, setLimits] = useState<{ days: string; uses: string } | null>(null);
  const rotate = useAction(() => api("/config/agent/rotate", { method: "POST" }), { success: "New enrolment key. Agents already installed keep working.", invalidate: ["/config/agent"] });
  const hours = useAction((h: number) => api("/config/agent", { method: "PATCH", body: { report_hours: h } }), { success: "Saved. Agents 1.2 and later pick it up at their next hourly check-in.", invalidate: ["/config"] });
  const saveLimits = useAction(() => api("/config/agent", { method: "PATCH", body: { set_key_limits: true, key_days: limits?.days ? Number(limits.days) : null, key_max_uses: limits?.uses ? Number(limits.uses) : null } }),
    { success: "Enrolment key limits saved.", invalidate: ["/config/agent"], onSuccess: () => setLimits(null) });
  if (!data) return <Skeleton className="h-64" />;
  const l = data.limits;
  return (
    <div className="max-w-4xl space-y-6">
      {!data.https && (
        <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-[#b07400]" />
          <div>Keystone's address is {data.server}. Agents only talk to HTTPS addresses (HTTP works for localhost testing only). Set KEYSTONE_PUBLIC_URL to the HTTPS address users reach Keystone on.</div></div>
      )}
      <p className="text-sm text-muted-foreground">The agents only read settings and send them to Keystone. They never change the host or run commands, and Keystone can't update them: you install new versions yourself. They also evaluate your custom checks (read-only, within limits built into the agent) unless installed with custom checks turned off. Each agent swaps the enrolment key for its own device token when it enrols, checks in every hour, and sends a full report when one is due. It also reports the SHA-256 of its own script, so a changed agent shows up as “Modified agent”, and lists installed software (leave it out with --no-software / -NoSoftware).</p>
      {AGENT_PLATFORMS.map((p) => (
        <Card key={p.key}>
          <CardHeader title={`${p.title} · agent ${data.files[p.key].version}`} description={p.about}
            action={<a href={downloadUrl(`/config/agent/download/${p.key}`)}><Button size="sm" variant="outline"><Download /> {data.files[p.key].filename}</Button></a>} />
          <CardBody className="space-y-3 text-sm">
            <div className="text-xs text-muted-foreground">SHA-256 <span className="break-all font-mono">{data.files[p.key].sha256}</span>{data.files[p.key].signed && <Badge tone="good" className="ml-2">Signed (Authenticode)</Badge>}</div>
            <Field label="Check the download before installing">
              <div className="flex items-start gap-2"><code className="block min-w-0 flex-1 break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">{data.verify[p.key]}</code><CopyButton text={data.verify[p.key]} /></div>
            </Field>
            <Field label={p.install}>
              <div className="flex items-start gap-2"><code className="block min-w-0 flex-1 break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">{data.install[p.key]}</code><CopyButton text={data.install[p.key]} /></div>
            </Field>
            <div className="text-xs text-muted-foreground">Options: <code className="font-mono">{data.options[p.key]}</code></div>
            <div className="text-xs text-muted-foreground">To remove: <code className="font-mono">{data.uninstall[p.key]}</code></div>
          </CardBody>
        </Card>
      ))}
      <Card>
        <CardHeader title="Enrolment key" description={data.rotated_at ? `Created ${fmtDate(data.rotated_at, true)}` : undefined}
          action={<Button size="sm" variant="outline" loading={rotate.isPending} onClick={() => window.confirm("Create a new enrolment key? The current one stops working for new installs.") && rotate.mutate(undefined)}><RotateCcw /> New key</Button>} />
        <CardBody className="space-y-3 text-sm">
          <div className="flex items-center gap-2"><KeyRound className="size-4 text-muted-foreground" /><code className="break-all font-mono text-xs">{data.enrolment_key}</code><CopyButton text={data.enrolment_key} /></div>
          {(l.expired || l.used_up) && <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-[#b07400]" aria-hidden />
            {l.expired ? "This key has expired." : "This key has been used as many times as allowed."} Create a new key to install more agents.</div>}
          <p className="text-muted-foreground">Anyone with this key can enrol a device, so share it only with the people installing agents and replace it when they're done. Revoke a device's token from its page under Hosts and firewalls.</p>
          <div className="rounded-lg border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span><span className="font-medium">Limits: </span>{l.expires_at ? `expires ${fmtDate(l.expires_at, true)}` : "never expires"} · {l.max_uses ? `${l.uses} of ${l.max_uses} enrolments used` : `${l.uses} enrolment(s), no limit`}</span>
              {!limits && <Button size="sm" variant="outline" onClick={() => setLimits({ days: l.days ? String(l.days) : "", uses: l.max_uses ? String(l.max_uses) : "" })}>Change limits</Button>}
            </div>
            {limits && (
              <div className="mt-3 flex flex-wrap items-end gap-3">
                <Field label="Expires after (days)" hint="Empty: never. Applies from now, and to each new key."><Input type="number" min={1} max={90} value={limits.days} onChange={(e) => setLimits({ ...limits, days: e.target.value })} className="w-32" /></Field>
                <Field label="At most this many enrolments" hint="Empty: no limit"><Input type="number" min={1} max={10000} value={limits.uses} onChange={(e) => setLimits({ ...limits, uses: e.target.value })} className="w-32" /></Field>
                <Button size="sm" loading={saveLimits.isPending} onClick={() => saveLimits.mutate(undefined)}>Save limits</Button>
                <Button size="sm" variant="ghost" onClick={() => setLimits(null)}>Cancel</Button>
              </div>
            )}
          </div>
          <Field label="Report at least every"><Select ariaLabel="Report interval" value={String(data.report_hours)} onChange={(v) => v && hours.mutate(Number(v))} options={[1, 2, 4, 8, 12, 24].map((h) => ({ value: String(h), label: `${h} hour${h > 1 ? "s" : ""}` }))} className="w-40" /></Field>
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Pinning Keystone's key (optional)" description="For networks where TLS might be intercepted: the agent then accepts only a server whose public key matches, on top of the normal certificate checks." />
        <CardBody className="space-y-3 text-sm">
          <p className="text-muted-foreground">Get the pin of the key your server uses now, and add it at install with the --pin (Windows: -Pin) option. Many certificate renewals change the key: before renewing, either keep the key (for example certbot --reuse-key) or reinstall agents with two pins, the current key's and the next one's, separated by a semicolon. A wrong pin stops the agent reporting.</p>
          <CodeBlockLine text={`openssl s_client -connect ${data.server.replace(/^https?:\/\//, "").replace(/\/.*$/, "")}:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 | sed 's#^#sha256//#'`} />
        </CardBody>
      </Card>
    </div>
  );
}

function CodeBlockLine({ text }: { text: string }) {
  return <div className="flex items-start gap-2"><code className="block min-w-0 flex-1 break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">{text}</code><CopyButton text={text} /></div>;
}

// ---------------------------------------------------------------- installed software

function InstalledSoftware({ t }: { t: any }) {
  const [q, setQ] = useState("");
  const list: [string, string][] = t.software ?? [];
  const shown = list.filter(([n]) => !q || n.toLowerCase().includes(q.toLowerCase())).slice(0, 300);
  return (
    <Section title={`Installed software${list.length ? ` (${list.length})` : ""}`}>
      {!t.software_at ? <p className="text-sm text-muted-foreground">Not reported. Agents 1.2 and later list installed software with each full report, unless installed with --no-software.</p> : (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">Reported {fmtDate(t.software_at, true)}{t.platform === "linux" ? ". On Debian, Ubuntu, AlmaLinux and Rocky Linux these are matched against public vulnerability data when the “Keystone agents” source is connected (Integrations); results appear under Attack surface → Vulnerabilities." : "."}</p>
          <Input aria-label="Search installed software" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} className="max-w-xs" />
          <ul className="max-h-80 divide-y overflow-y-auto rounded-lg border text-sm">
            {shown.map(([n, v]) => <li key={`${n}@${v}`} className="flex justify-between gap-3 px-3 py-1.5"><span className="min-w-0 truncate">{n}</span><span className="shrink-0 font-mono text-xs text-muted-foreground">{v}</span></li>)}
            {shown.length === 0 && <li className="px-3 py-2 text-muted-foreground">Nothing matches.</li>}
          </ul>
        </div>
      )}
    </Section>
  );
}

function Software() {
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const { data } = useApi<any>(`/config/software?q=${encodeURIComponent(query)}&limit=200`);
  const [, setParams] = useSearchParams();
  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-sm text-muted-foreground">Installed software reported by agents 1.2 and later: Linux packages, Windows programs and Mac apps. Search for a product to see which hosts have which version.</p>
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); setQuery(q.trim()); }}>
        <Input aria-label="Software name" placeholder="e.g. openssl, Chrome" value={q} onChange={(e) => setQ(e.target.value)} className="max-w-sm" />
        <Button type="submit" variant="outline">Search</Button>
      </form>
      {!data ? <Skeleton className="h-48" /> : data.hosts === 0 ? (
        <Empty icon={Boxes} title="No software reported yet">Agents 1.2 and later list installed software with each full report.</Empty>
      ) : (
        <>
          <p className="text-xs text-muted-foreground">{data.total} name and version pair(s) across {data.hosts} host(s){data.total > data.rows.length ? `; showing the ${data.rows.length} most widespread` : ""}.</p>
          <DataTable rows={data.rows} rowKey={(r: any) => `${r.name}@${r.version}`} exportName="installed-software" columns={[
            { key: "n", header: "Software", cell: (r: any) => <span className="font-medium">{r.name}</span> },
            { key: "v", header: "Version", cell: (r: any) => <span className="font-mono text-xs">{r.version}</span> },
            { key: "h", header: "Hosts", cell: (r: any) => (
              <span className="flex flex-wrap gap-1">{r.hosts.slice(0, 8).map((h: any) => <Button key={h.id} size="sm" variant="ghost" onClick={() => setParams({ tab: "targets", target: String(h.id) })}>{h.name}</Button>)}
                {r.hosts.length > 8 && <span className="text-xs text-muted-foreground">+{r.hosts.length - 8} more</span>}</span>
            ) },
          ]} />
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- coverage

const OS_LABEL: Record<string, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };
const TOOL_LABEL: Record<string, string> = { rmm: "Remote management", edr: "Endpoint security", vuln: "Vulnerability scanner", mdm: "Device management", manual: "Imported list" };

function Coverage() {
  const { data } = useApi<any>("/config/coverage");
  const [, setParams] = useSearchParams();
  if (!data) return <Skeleton className="h-64" />;
  const openTarget = (t: any) => setParams({ tab: "targets", target: String(t.id) });
  return (
    <div className="space-y-6">
      <p className="max-w-3xl text-sm text-muted-foreground">Compares the hosts running a Keystone agent with the workstations and servers your other tools (Attack surface sources) reported in the last {data.days} days, matched by host name.</p>
      {data.devices === 0 && data.not_in_tools.length === 0 ? (
        <Empty icon={Radar} title="Nothing to compare yet">Connect a remote management, endpoint security or device management tool under Integrations, then come back to see which devices have no agent.</Empty>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
            <Stat label="Devices your tools know" value={data.devices} />
            <Stat label="With a Keystone agent" value={data.percent === null ? "—" : `${data.percent}%`} hint={`${data.with_agent} of ${data.devices}`} tone={data.percent === 100 ? "good" : undefined} />
            <Stat label="No agent" value={data.no_agent_count} tone={data.no_agent_count ? "warning" : undefined} />
            <Stat label="Agent but no endpoint security" value={data.edr_source ? data.no_edr.length : "—"} hint={data.edr_source ? undefined : "No endpoint security tool connected"} tone={data.no_edr.length ? "critical" : undefined} />
          </div>
          <Section title="Devices without an agent" level={2}>
            <DataTable rows={data.no_agent} rowKey={(d: any) => d.id} exportName="devices-without-agent" empty="Every device your tools know has an agent." search={(d: any) => `${d.name} ${d.os ?? ""}`}
              columns={[
                { key: "n", header: "Device", cell: (d: any) => <span><span className="font-medium">{d.name}</span><span className="block text-xs text-muted-foreground">{d.os ?? ""}</span></span> },
                { key: "t", header: "Type", cell: (d: any) => titleCase(d.type) },
                { key: "s", header: "Seen by", cell: (d: any) => d.tools.map((c: string) => TOOL_LABEL[c] ?? c).join(", ") || "—" },
                { key: "l", header: "Last seen", cell: (d: any) => (d.last_seen ? fmtDate(d.last_seen, true) : "—") },
              ]} />
          </Section>
          {data.edr_source && (
            <Section title="Agents on hosts without endpoint security" level={2}>
              <DataTable rows={data.no_edr} rowKey={(t: any) => t.id} onRowClick={openTarget} empty="Every agent host also has endpoint security." columns={[
                { key: "n", header: "Host", cell: (t: any) => <span className="font-medium">{t.name}</span> },
                { key: "p", header: "Platform", cell: (t: any) => OS_LABEL[t.platform] ?? t.platform },
              ]} />
            </Section>
          )}
          <Section title="Agent hosts your other tools don't know" level={2}>
            <p className="mb-2 text-xs text-muted-foreground">Either the host name differs between tools, or the host isn't managed by them.</p>
            <DataTable rows={data.not_in_tools} rowKey={(t: any) => t.id} onRowClick={openTarget} empty="Every agent host is known to your other tools." columns={[
              { key: "n", header: "Host", cell: (t: any) => <span className="font-medium">{t.name}</span> },
              { key: "p", header: "Platform", cell: (t: any) => OS_LABEL[t.platform] ?? t.platform },
            ]} />
          </Section>
        </>
      )}
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
      <p className="text-sm text-muted-foreground">Keystone reads the settings it checks, and your custom checks for this platform, from the file. It keeps only those values and the file's SHA-256. The file itself is not stored, because configuration exports contain password hashes and keys. After adding custom checks, upload the configuration again to evaluate them.</p>
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
