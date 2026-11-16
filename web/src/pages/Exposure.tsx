import { useEffect, useState } from "react";
import { AlertTriangle, Check, Download, EyeOff, Map as MapIcon, RefreshCw, Upload } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase, tri } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Sheet } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Empty, PageHeader, Section, Skeleton, Stat } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { LevelBadge } from "@/components/ui/status";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";

export default function Exposure() {
  return (
    <div className="animate-fade-in">
      <PageHeader icon={MapIcon} title="Entra exposure" description="Third-party apps in your Microsoft Entra ID tenants, collected read-only by the PowerShell collector. Unknown is never shown as safe." />
      <Tabs tabs={[
        { value: "map", label: "Exposure map", content: <TenantMap /> },
        { value: "cross", label: "Cross-tenant", content: <CrossTenant /> },
        { value: "match", label: "Vendor matching", content: <Matching /> },
        { value: "rem", label: "Remediation", content: <Remediation /> },
        { value: "imp", label: "Import", content: <Import /> },
      ]} />
    </div>
  );
}

function TenantMap() {
  const tenants = useApi<any[]>("/exposure/tenants");
  const [tid, setTid] = useState<string | null>(null);
  useEffect(() => { if (!tid && tenants.data?.length) setTid(String(tenants.data[0].id)); }, [tenants.data, tid]);
  const { data } = useApi<any>(tid ? `/exposure/tenants/${tid}` : null);
  const [classes, setClasses] = useState<string | null>("vendors");
  const [open, setOpen] = useState<number | null>(null);
  if (!tenants.data) return <Skeleton className="h-64" />;
  if (!tenants.data.length) return <Empty icon={MapIcon} title="No exposure data yet">Run collector/Invoke-VendorExposureCollector.ps1 and import collected.json on the Import tab.</Empty>;
  const apps = (data?.apps ?? []).filter((a: any) => classes === "all" || (classes === "vendors" ? ["third_party", "unknown"].includes(a.owner_class) : a.owner_class === classes));
  const bad = data ? Object.entries(data.snapshot.endpoint_status).filter(([, v]: any) => v.status !== "ok") : [];
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Tenant" className="w-72"><Select value={tid} onChange={setTid} options={tenants.data.map((t) => ({ value: String(t.id), label: t.name }))} /></Field>
        <Field label="Show" className="w-56"><Select value={classes} onChange={setClasses} options={[{ value: "vendors", label: "Third-party and unknown" }, { value: "internal", label: "Internal" }, { value: "microsoft", label: "Microsoft" }, { value: "all", label: "All apps" }]} /></Field>
      </div>
      {!data ? <Skeleton className="h-64" /> : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Collected" value={fmtDate(data.snapshot.collected_at_utc)} hint={`by ${data.snapshot.operator_upn}`} />
            <Stat label="Entra ID P1/P2" value={tri(data.snapshot.entra_p1_available)} />
            <Stat label="Users can consent" value={tri(data.consent?.users_can_consent)} tone={data.consent?.users_can_consent ? "critical" : undefined} />
            <Stat label="Admin consent workflow" value={tri(data.consent?.admin_consent_workflow_enabled, "Enabled", "Disabled")} />
          </div>
          {data.snapshot.write_scopes_present && <Banner tone="warning">Write-capable scopes were present on the collector's token (standing consent to Graph Command Line Tools). Review that consent.</Banner>}
          {bad.map(([k, v]: any) => <Banner key={k} tone={["unavailable_license", "skipped"].includes(v.status) ? "warning" : "critical"}><b>{k}</b>: {v.status}{v.http_status ? ` (HTTP ${v.http_status})` : ""}{v.message ? `: ${v.message}` : ""}. Results that depend on it are shown as unknown.</Banner>)}
          <DataTable rows={apps} rowKey={(a: any) => a.id} onRowClick={(a: any) => setOpen(a.id)} search={(a: any) => `${a.display_name} ${a.publisher_name ?? ""}`} columns={[
            { key: "n", header: "App", cell: (a: any) => <div><div className="font-medium">{a.display_name}</div><div className="text-xs text-muted-foreground">{a.verified_publisher_name ?? a.publisher_name ?? "Unknown publisher"}{a.publisher_verified && " ✓ verified"}</div></div>, sort: (a: any) => a.display_name },
            { key: "o", header: "Owner", cell: (a: any) => <Badge tone={a.owner_class === "unknown" ? "warning" : "outline"}>{titleCase(a.owner_class)}</Badge> },
            { key: "e", header: "Exposure", cell: (a: any) => <div className="flex items-center gap-1"><LevelBadge level={a.exposure?.exposure_level} />{a.exposure?.incomplete_data && <span title="Partial data"><AlertTriangle className="size-4 text-warning" /></span>}</div>, sort: (a: any) => ["Low", "Medium", "High", "Critical"].indexOf(a.exposure?.exposure_level) },
            { key: "ao", header: "App-only", cell: (a: any) => (a.exposure?.has_app_only ? <Badge tone="serious">Yes</Badge> : "No") },
            { key: "uc", header: "Users consented", cell: (a: any) => a.exposure?.user_consent_count || "—", className: "text-right" },
            { key: "d", header: "Dormant", cell: (a: any) => (a.exposure?.dormant === null ? <span className="text-muted-foreground">Unknown</span> : a.exposure?.dormant ? <Badge tone="warning">Yes</Badge> : "No") },
            { key: "ls", header: "Last sign-in", cell: (a: any) => (a.sign_in_data_available ? fmtDate(a.last_sign_in_utc) : "unknown") },
          ]} />
          {data.diff && (
            <Card>
              <CardHeader title="Changes since the previous snapshot" description="Newly added app-only critical and high permissions first." />
              <CardBody className="space-y-3 text-sm">
                {data.diff.not_comparable.length > 0 && <Banner tone="warning">Not comparable: {data.diff.not_comparable.join(", ")}</Banner>}
                <div className="grid gap-3 sm:grid-cols-2"><div><b>New apps:</b> {data.diff.new_apps.join(", ") || "none"}</div><div><b>Removed apps:</b> {data.diff.removed_apps.join(", ") || "none"}</div></div>
                <DataTable rows={data.diff.new_permissions} rowKey={(p: any) => `${p.app}-${p.value}-${p.permission_type}`} empty="No new permissions." columns={[
                  { key: "f", header: "", cell: (p: any) => (p.app_only_high ? <AlertTriangle className="size-4 text-critical" /> : null), className: "w-8" },
                  { key: "a", header: "App", cell: (p: any) => p.app },
                  { key: "t", header: "Type", cell: (p: any) => p.permission_type },
                  { key: "v", header: "Permission", cell: (p: any) => <code className="text-xs">{p.value}</code> },
                  { key: "ti", header: "Tier", cell: (p: any) => titleCase(p.tier) },
                ]} />
                {data.diff.consent_changes.length > 0 && <div><b>Consent changes:</b> {data.diff.consent_changes.map((c: any) => `${c[0]}: ${tri(c[1])} → ${tri(c[2])}`).join("; ")}</div>}
                {data.diff.new_credentials.length > 0 && <div><b>New credentials:</b> {data.diff.new_credentials.map((c: any) => `${c[0]} (${c[1]}: ${c[2]})`).join("; ")}</div>}
              </CardBody>
            </Card>
          )}
        </>
      )}
      {open && <AppDrawer id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

function Banner({ tone, children }: { tone: "warning" | "critical"; children: any }) {
  return <div className={`flex items-start gap-2 rounded-lg border px-4 py-3 text-sm ${tone === "critical" ? "border-critical/30 bg-critical/5" : "border-warning/40 bg-warning/10"}`}><AlertTriangle className={`mt-0.5 size-4 shrink-0 ${tone === "critical" ? "text-critical" : "text-[#b07400]"}`} /><div>{children}</div></div>;
}

function AppDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { data } = useApi<any>(`/exposure/apps/${id}`);
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data?.display_name ?? "Loading…"} subtitle={data && <span className="flex items-center gap-2"><LevelBadge level={data.exposure?.exposure_level} /> {titleCase(data.owner_class)}</span>}>
      {!data ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <Section title="Why this level">
            <ul className="space-y-2">{data.exposure.reasons.map((r: any, i: number) => <li key={i} className="flex gap-2 text-sm"><code className="h-fit shrink-0 rounded bg-muted px-1.5 text-xs">{r.rule_id}</code>{r.text}</li>)}</ul>
          </Section>
          <Section title="Permissions">
            <DataTable rows={data.permissions} rowKey={(p: any) => `${p.permission_type}${p.value}${p.resource_name}${p.consent_type}`} empty="No API permissions." columns={[
              { key: "t", header: "Type", cell: (p: any) => p.permission_type },
              { key: "v", header: "Permission", cell: (p: any) => <code className="text-xs">{p.value}</code> },
              { key: "r", header: "Resource", cell: (p: any) => p.resource_name },
              { key: "ti", header: "Tier", cell: (p: any) => titleCase(p.tier) },
              { key: "c", header: "Consent", cell: (p: any) => (p.consent_type === "AllPrincipals" ? "Admin (all users)" : p.consent_type === "Principal" ? `${p.user_count} user(s)` : "App-only") },
            ]} />
          </Section>
          <Section title="Credentials">
            {data.credentials === null ? <Banner tone="warning">Credential data could not be collected for this tenant: unknown.</Banner> : (
              <DataTable rows={data.credentials} rowKey={(c: any) => `${c.display_name}${c.end_utc}`} empty="No credentials visible in this tenant." columns={[
                { key: "o", header: "On", cell: (c: any) => c.owner_type },
                { key: "t", header: "Type", cell: (c: any) => c.credential_type },
                { key: "n", header: "Name", cell: (c: any) => c.display_name },
                { key: "e", header: "Ends", cell: (c: any) => fmtDate(c.end_utc) },
                { key: "s", header: "Status", cell: (c: any) => <Badge tone={c.status === "expired" ? "critical" : c.status === "expiring_30d" ? "warning" : "good"}>{titleCase(c.status)}</Badge> },
              ]} />
            )}
          </Section>
          <p className="text-xs text-muted-foreground">App ID {data.app_id} · owner org {data.owner_org_id ?? "unknown"} · reply domains {data.reply_url_domains.join(", ") || "—"}</p>
        </div>
      )}
    </Sheet>
  );
}

function CrossTenant() {
  const { data } = useApi<any>("/exposure/cross-tenant");
  if (!data) return <Skeleton className="h-64" />;
  const order = ["Low", "Medium", "High", "Critical"];
  const rows = data.rows.map((r: any) => ({ ...r, ch: Object.values(r.levels).filter((l: any) => l === "Critical" || l === "High").length })).sort((a: any, b: any) => b.ch - a.ch);
  return (
    <DataTable rows={rows} rowKey={(r: any) => r.owner_org_id} search={(r: any) => `${r.vendor ?? ""} ${r.label}`} columns={[
      { key: "v", header: "Vendor / owner organisation", cell: (r: any) => (r.vendor ? <span className="font-medium">{r.vendor}</span> : <span className="text-muted-foreground">{r.label} (unmapped)</span>) },
      { key: "ch", header: "Tenants at Critical/High", cell: (r: any) => r.ch, sort: (r: any) => r.ch, className: "text-right" },
      ...data.tenants.map((t: any) => ({ key: `t${t.id}`, header: t.name, cell: (r: any) => (r.levels[String(t.id)] ? <LevelBadge level={r.levels[String(t.id)]} /> : <span className="text-muted-foreground">—</span>), sort: (r: any) => order.indexOf(r.levels[String(t.id)]) })),
    ]} />
  );
}

function Matching() {
  const { can } = useAuth();
  const { data } = useApi<any>("/exposure/matching");
  const vendors = useApi<any>("/vendors");
  const [pick, setPick] = useState<Record<string, string | null>>({});
  const inv = ["/exposure", "/vendors", "/assessments"];
  const refresh = useAction(() => api("/exposure/matching/refresh", { method: "POST" }), { success: "Suggestions refreshed.", invalidate: inv });
  const confirm = useAction((v: { oid: string; vid: number }) => api(`/exposure/matching/${v.oid}/confirm`, { body: { vendor_id: v.vid } }), { success: "Mapping confirmed. It applies to every tenant.", invalidate: inv });
  const ignore = useAction((oid: string) => api(`/exposure/matching/${oid}/ignore`, { method: "POST" }), { success: "Ignored.", invalidate: inv });
  const reset = useAction((oid: string) => api(`/exposure/matching/${oid}`, { method: "DELETE" }), { success: "Decision removed.", invalidate: inv });
  if (!data) return <Skeleton className="h-64" />;
  const vopts = (vendors.data?.vendors ?? []).map((v: any) => ({ value: String(v.id), label: v.name }));
  const vname = new Map((vendors.data?.vendors ?? []).map((v: any) => [v.id, v.name]));
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">Map each app publisher (the vendor's own Entra tenant) to a Keystone vendor. Nothing is applied until you confirm.</p>
        {can("exposure.import") && <Button variant="outline" loading={refresh.isPending} onClick={() => refresh.mutate(undefined)}><RefreshCw /> Refresh suggestions</Button>}
      </div>
      {data.queue.length === 0 ? <Empty icon={Check} title="Nothing to match">Every third-party owner organisation has a decision.</Empty> : data.queue.map((q: any) => {
        const top = q.candidates[0];
        const sel = pick[q.owner_org_id] ?? (top ? String(top.vendor_id) : null);
        return (
          <Card key={q.owner_org_id}>
            <CardBody>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 font-medium"><LevelBadge level={q.worst} /> {q.apps.join(", ")}</div>
                  <div className="mt-1 text-xs text-muted-foreground">Names: {q.names.join("; ")} · domains: {q.domains.join(", ") || "—"} · in {q.tenants} tenant(s)</div>
                </div>
                {top && <Badge tone={top.strength === "strong" ? "good" : "outline"}>{top.strength} match: {top.vendor} ({top.name_score}{top.domain_match ? ", domain ✓" : ""})</Badge>}
              </div>
              {can("exposure.confirm") && (
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <div className="w-64"><Select value={sel} onChange={(v) => setPick({ ...pick, [q.owner_org_id]: v })} options={vopts} placeholder="Choose vendor" /></div>
                  <Button size="sm" disabled={!sel} onClick={() => sel && confirm.mutate({ oid: q.owner_org_id, vid: Number(sel) })}><Check /> Confirm</Button>
                  <Button size="sm" variant="ghost" onClick={() => ignore.mutate(q.owner_org_id)}><EyeOff /> Ignore</Button>
                </div>
              )}
            </CardBody>
          </Card>
        );
      })}
      <Section title="Decisions">
        <DataTable rows={data.decided} rowKey={(d: any) => d.owner_org_id} empty="No decisions yet." columns={[
          { key: "o", header: "Owner org", cell: (d: any) => <code className="text-xs">{d.owner_org_id}</code> },
          { key: "s", header: "Decision", cell: (d: any) => (d.status === "confirmed" ? <Badge tone="good">→ {vname.get(d.vendor_id) as string}</Badge> : <Badge tone="outline">Ignored</Badge>) },
          { key: "b", header: "By", cell: (d: any) => `${d.confirmed_by ?? ""} ${fmtDate(d.confirmed_at)}` },
          { key: "x", header: "", cell: (d: any) => can("exposure.confirm") && <Button size="sm" variant="ghost" onClick={() => reset.mutate(d.owner_org_id)}>Undo</Button> },
        ]} />
      </Section>
    </div>
  );
}

const REM: Record<string, [string, string]> = {
  dormant_high_risk: ["Dormant apps at High or Critical exposure", "Remove the app or its permissions if no longer used."],
  unverified_user_consented: ["Unverified publishers with user consent", "Review the grants; consider revoking and restricting user consent."],
  expired_credentials: ["Expired credentials still present", "Delete expired secrets and certificates."],
  sp_credentials_on_vendor_apps: ["Credentials added to vendor apps in your tenant", "Confirm who added them; unexpected credentials can be an attacker's persistence."],
  users_can_consent: ["Tenants where users can consent to apps", "Restrict user consent and enable the admin consent workflow."],
};

function Remediation() {
  const { data } = useApi<any>("/exposure/remediation");
  if (!data) return <Skeleton className="h-64" />;
  return (
    <div className="space-y-4">
      <div className="flex justify-between"><p className="text-sm text-muted-foreground">Read-only findings to act on in Entra ID. Keystone makes no changes to your tenants.</p><a href={downloadUrl("/exposure/remediation.xlsx")}><Button variant="outline"><Download /> Excel</Button></a></div>
      {Object.entries(REM).map(([k, [title, advice]]) => (
        <Card key={k}>
          <CardHeader title={<span className="flex items-center gap-2">{title} <Badge tone={data[k].length ? "warning" : "good"}>{data[k].length}</Badge></span>} description={advice} />
          {data[k].length > 0 && <CardBody className="p-3"><DataTable rows={data[k]} rowKey={(r: any) => JSON.stringify(r)} columns={Object.keys(data[k][0]).map((c) => ({ key: c, header: c, cell: (r: any) => String(r[c] ?? "—") }))} /></CardBody>}
        </Card>
      ))}
    </div>
  );
}

function Import() {
  const { can } = useAuth();
  const [file, setFile] = useState<File | null>(null);
  const [prev, setPrev] = useState<any>(null);
  const [name, setName] = useState("");
  const preview = useAction(async () => { const fd = new FormData(); fd.append("file", file as File); return upload("/exposure/preview", fd); }, { onSuccess: (r: any) => { setPrev(r); setName(r.tenant_name ?? ""); } });
  const doImport = useAction(async () => { const fd = new FormData(); fd.append("file", file as File); if (!prev.existing_tenant) fd.append("tenant_name", name); return upload("/exposure/import", fd); }, { success: (r: any) => `Imported ${r.apps} apps.`, invalidate: ["/exposure", "/vendors", "/dashboard"], onSuccess: () => { setPrev(null); setFile(null); } });
  if (!can("exposure.import")) return <Empty title="Your role cannot import exposure data." />;
  return (
    <div className="max-w-3xl space-y-4">
      <Banner tone="warning">The collector output is a map of your attack surface. Delete it from the technician's workstation after import.</Banner>
      <div className="flex items-center gap-3"><input type="file" accept=".json" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setPrev(null); }} className="text-sm" /><Button variant="outline" disabled={!file} loading={preview.isPending} onClick={() => preview.mutate(undefined)}><Upload /> Check file</Button></div>
      {prev && !prev.valid && <Banner tone="critical"><div className="font-medium">This file does not match the collected.json schema.</div><ul className="mt-1 list-disc pl-5 text-xs">{prev.errors.map((e: string) => <li key={e}>{e}</li>)}</ul></Banner>}
      {prev?.valid && (
        <Card>
          <CardHeader title={`${prev.tenant_name} · collected ${fmtDate(prev.collected_at, true)}`} description={`Entra tenant ${prev.tenant_id} · by ${prev.operator} · P1/P2: ${tri(prev.entra_p1_available)}`} />
          <CardBody className="space-y-3">
            {prev.write_scopes_present && <Banner tone="warning">Write-capable scopes were present on the token. The collector only read data, but review that standing consent.</Banner>}
            {prev.problems.map(([sev, k, m]: any) => <Banner key={k} tone={sev === "error" ? "critical" : "warning"}><b>{k}</b>: {m}</Banner>)}
            <div className="grid gap-2 sm:grid-cols-4">{Object.entries(prev.counts).map(([k, v]: any) => <div key={k} className="rounded-md border px-3 py-2 text-sm"><div className="text-xs text-muted-foreground">{titleCase(k)}</div><div className="font-medium">{v === null ? "could not check" : v}</div></div>)}</div>
            {prev.duplicate ? <Banner tone="critical">This snapshot has already been imported.</Banner> : (
              <>
                {prev.existing_tenant ? <p className="text-sm">Adds a snapshot to <b>{prev.existing_tenant}</b>.</p> : <Field label="Register this new tenant as"><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>}
                <Button loading={doImport.isPending} onClick={() => doImport.mutate(undefined)}>Import snapshot</Button>
              </>
            )}
          </CardBody>
        </Card>
      )}
    </div>
  );
}
