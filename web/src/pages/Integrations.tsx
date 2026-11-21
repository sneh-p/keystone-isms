import { useState } from "react";
import { Link } from "react-router";
import { AlertTriangle, ArrowRight, Cloud, ExternalLink, FlaskConical, Github, Globe, KeyRound, Play, Plug, Settings2, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, useUrlFilter } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { cn, fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { PageHeader, Section, Skeleton, Stat, Switch } from "@/components/ui/misc";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { CodeBlock } from "@/components/CopyButton";
import { DateInput } from "@/components/forms";
import { safeHref } from "@/lib/safe-url";

const ICON: Record<string, any> = { website: Globe, github: Github, aws: Cloud, entra: ShieldCheck };

const CATEGORY: Record<string, string> = { rmm: "devices (RMM)", edr: "EDR", vuln: "vulnerabilities", mdm: "device management", identity: "identities", posture: "cloud and tenant configuration" };

export default function Integrations() {
  const { can } = useAuth();
  const { data } = useApi<any>("/integrations");
  const [connect, setConnect] = useState<any>(null);
  const [openParam, setOpenParam] = useUrlFilter("open");
  const open = openParam ? Number(openParam) : null;
  const setOpen = (id: number | null) => setOpenParam(id ? String(id) : null);
  const save = useAction((b: any) => {
    const common = { name: b.name, values: b.values, schedule_hours: b.schedule_hours, credential_expires_on: b.credential_expires_on || null };
    return b.id ? api(`/integrations/${b.id}`, { method: "PATCH", body: { ...common, clear_credential_expiry: !b.credential_expires_on } }) : api("/integrations", { body: { provider: b.provider, ...common } });
  }, { success: "Integration saved. Run it to see results.", invalidate: ["/integrations"], onSuccess: (r: any) => { setConnect(null); setOpen(r.id); } });
  if (!data) return <Skeleton className="h-96" />;
  const all = data.integrations.flatMap((i: any) => i.results);
  const failing = all.filter((r: any) => r.result === "fail").length;
  const attention = data.integrations.filter((i: any) => i.health.escalated || i.health.overdue || i.health.credential_expiring).length;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Plug} title="Integrations" description="Read-only connections that test your controls automatically. Passing checks become evidence; failing, erroring or unknown checks never count as passing." />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        <Stat label="Connected" value={data.integrations.length} />
        <Stat label="Checks passing" value={all.filter((r: any) => r.result === "pass").length} tone="good" />
        <Stat label="Checks failing" value={failing} tone={failing ? "critical" : undefined} />
        <Stat label="Need attention" value={attention} tone={attention ? "warning" : undefined} hint="Failing runs, overdue, or a key expiring" />
      </div>
      {[["Control checks", (p: any) => !p.inventory && !p.ticketing && !p.hr], ["Attack surface sources", (p: any) => p.inventory], ["Ticketing", (p: any) => p.ticketing], ["HR systems", (p: any) => p.hr]].map(([title, test]: any) => {
        const list = data.providers.filter(test);
        if (!list.length) return null;
        return (
          <section key={title} className="mb-6" aria-label={title}>
            <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-muted-foreground">{title}</h2>
            {title === "HR systems" && <p className="mb-3 text-sm text-muted-foreground">Keep <Link to="/people" className="text-primary underline">People</Link> in step with your HR system: joiners are added for onboarding, and leavers move to offboarding with a notification. Read-only: names, work emails, titles, departments and dates only.</p>}
            {title === "Ticketing" && <p className="mb-3 text-sm text-muted-foreground">Open a ticket in your service desk from a vulnerability, finding, task or nonconformity, and see when it's closed. Keystone only creates tickets and reads their status; it never edits or closes them.</p>}
            {title === "Attack surface sources" && <p className="mb-3 text-sm text-muted-foreground">Read-only device, identity, vulnerability and configuration data for <Link to="/attack-surface" className="text-primary underline">Attack surface</Link>, checked against your baselines.</p>}
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {list.map((p: any) => {
                const Icon = ICON[p.key] ?? Plug;
                const mine = data.integrations.filter((i: any) => i.provider === p.key);
                return (
                  <Card key={p.key} className="flex flex-col">
                    <CardBody className="flex flex-1 flex-col">
                      <div className="flex items-center gap-3"><div className="rounded-lg bg-accent p-2 text-accent-foreground"><Icon className="size-5" /></div><div className="font-semibold leading-tight">{p.name}</div></div>
                      <p className="mt-3 flex-1 text-sm text-muted-foreground">{p.description}</p>
                      <div className="mt-3 text-xs text-muted-foreground">{p.hr ? "Joiners, movers and leavers" : p.ticketing ? "Creates tickets; reads their status" : p.inventory ? `Provides: ${p.categories.map((c: string) => CATEGORY[c] ?? c).join(", ")}` : `${p.checks.length} checks · maps to ${[...new Set(p.checks.flatMap((c: any) => c.controls))].length} controls`}</div>
                      <div className="mt-4 flex flex-wrap gap-2">
                        {mine.map((i: any) => <Button key={i.id} size="sm" variant="secondary" onClick={() => setOpen(i.id)}>{i.name} <StatusBadge status={i.last_status === "error" ? "error" : i.results.some((r: any) => r.result === "fail") ? "fail" : i.results.length ? "pass" : "unknown"} label=" " />{i.health.credential_expiring && <KeyRound className="size-3.5 text-warning" aria-label="Key expiring" />}</Button>)}
                        {can("integration.manage") && <Button size="sm" variant="outline" onClick={() => setConnect({ provider: p.key, name: p.name, values: {}, schedule_hours: p.ticketing ? 1 : p.inventory ? 6 : 24 })}>Connect</Button>}
                      </div>
                    </CardBody>
                  </Card>
                );
              })}
            </div>
          </section>
        );
      })}
      {connect && <ConnectDialog connect={connect} setConnect={setConnect} provider={data.providers.find((p: any) => p.key === connect.provider)} saving={save.isPending} onSave={() => save.mutate(connect)} />}
      {open && <IntegrationDrawer id={open} providers={data.providers} integrations={data.integrations} onClose={() => setOpen(null)} onEdit={(c: any) => setConnect(c)} />}
    </div>
  );
}

function IntegrationDrawer({ id, providers, integrations, onClose, onEdit }: any) {
  const { can } = useAuth();
  const i = integrations.find((x: any) => x.id === id);
  const p = providers.find((x: any) => x.key === i?.provider);
  const hist = useApi<any[]>(`/integrations/${id}/history`);
  const run = useAction(() => api(`/integrations/${id}/run`, { method: "POST" }), { success: "Checks complete.", invalidate: ["/integrations", "/controls", "/evidence", "/dashboard"] });
  const toggle = useAction((v: boolean) => api(`/integrations/${id}`, { method: "PATCH", body: { enabled: v } }), { invalidate: ["/integrations"] });
  if (!i) return null;
  const ed = can("integration.manage");
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={i.name} subtitle={`${p?.name} · ${i.last_run_at ? `last run ${fmtDate(i.last_run_at, true)}` : "never run"} · every ${i.schedule_hours}h`}
      actions={ed && <><Button size="sm" variant="outline" onClick={() => onEdit({ id: i.id, provider: i.provider, name: i.name, values: { ...i.config }, schedule_hours: i.schedule_hours, credential_expires_on: i.health.credential_expires_on })}><Settings2 /> Edit</Button><Button size="sm" loading={run.isPending} onClick={() => run.mutate(undefined)}><Play /> Run now</Button></>}>
      <div className="space-y-6">
        {ed && <Switch checked={i.enabled} onChange={(v) => toggle.mutate(v)} label={i.enabled ? "Runs on schedule" : "Paused"} />}
        {i.last_error && <div className="rounded-lg border border-critical/30 bg-critical/5 px-4 py-3 text-sm">{i.last_error}</div>}
        <Health h={i.health} schedule={i.schedule_hours} />
        <Section title="Latest results">
          {i.results.length === 0 ? <p className="text-sm text-muted-foreground">Not run yet.</p> : (
            <div className="space-y-2">{i.results.map((r: any) => (
              <div key={r.check_key} className="rounded-lg border p-3">
                <div className="flex items-start justify-between gap-2"><span className="font-medium">{r.title}</span><span className="flex gap-1">{r.flapping && <Badge tone="warning">Keeps changing</Badge>}<StatusBadge status={r.result} /></span></div>
                <p className="mt-1 text-sm text-muted-foreground">{r.summary}</p>
                {r.flapping && <p className="mt-1 text-xs text-muted-foreground">This check has changed between pass and fail several times recently, which usually means a timing or permission problem rather than a real change.</p>}
                <div className="mt-2 flex flex-wrap gap-1">{r.controls.map((c: string) => <Badge key={c} tone="primary" className="font-mono text-[10px]">{c}</Badge>)}</div>
              </div>
            ))}</div>
          )}
        </Section>
        <Section title="History">
          <DataTable rows={hist.data ?? []} rowKey={(r: any) => `${r.run_at}${r.check_key}`} empty="No runs yet." columns={[
            { key: "w", header: "When", cell: (r: any) => fmtDate(r.run_at, true) },
            { key: "c", header: "Check", cell: (r: any) => r.title },
            { key: "r", header: "Result", cell: (r: any) => <StatusBadge status={r.result} /> },
          ]} />
        </Section>
      </div>
    </Sheet>
  );
}

/** Failed runs in a row, the last good run, and when the stored key expires. */
function Health({ h, schedule }: { h: any; schedule: number }) {
  const rows: [string, string, string | undefined][] = [];
  if (h.consecutive_failures > 0) rows.push(["Failed runs in a row", `${h.consecutive_failures}${h.escalated ? " (the ISMS managers have been told)" : ""}`, h.escalated ? "critical" : "warning"]);
  rows.push(["Last successful run", h.last_success_at ? fmtDate(h.last_success_at, true) : "Never", h.overdue ? "warning" : undefined]);
  if (h.credential_expires_on) rows.push(["Key or secret expires", `${fmtDate(h.credential_expires_on)} (${h.credential_days_left < 0 ? `${-h.credential_days_left} days ago` : `in ${h.credential_days_left} days`})`, h.credential_expiring ? (h.credential_days_left < 0 ? "critical" : "warning") : undefined]);
  return (
    <div className="space-y-2">
      {h.overdue && <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />No successful run for more than twice the schedule ({schedule * 2} hours): results and evidence are getting old.</div>}
      <dl className="grid gap-2 text-sm sm:grid-cols-3">
        {rows.map(([k, v, tone]) => (
          <div key={k} className="rounded-lg border px-3 py-2"><dt className="text-xs text-muted-foreground">{k}</dt><dd className={cn("font-medium", tone === "critical" && "text-critical", tone === "warning" && "text-[#8a5a00] dark:text-warning")}>{v}</dd></div>
        ))}
      </dl>
    </div>
  );
}

/** Fill {field} placeholders from the form (non-secret fields only, plus {host} from a URL). Unknown braces are left alone. */
function fillPlaceholders(text: string, provider: any, values: Record<string, string>): string {
  const vals = new Map<string, string>();
  for (const f of provider.fields) if (!f.secret) vals.set(f.name, (values[f.name] ?? "").trim() || f.example || `<${f.label}>`);
  const url = vals.get("url");
  if (url) {
    try { vals.set("host", new URL(url.includes("://") ? url : `https://${url}`).hostname); } catch { vals.set("host", url); }
  }
  return text.replace(/\{(\w+)\}/g, (m, k) => vals.get(k) ?? m);
}

function SetupGuide({ provider, values }: { provider: any; values: Record<string, string> }) {
  if (!provider.setup?.length) return null;
  return (
    <ol className="space-y-5">
      {provider.setup.map((st: any, i: number) => {
        const filled = st.link ? fillPlaceholders(st.link, provider, values) : "";
        const link = filled.startsWith("/") ? filled : (safeHref(filled) ?? "");
        return (
          <li key={i} className="relative pl-9">
            <span className={cn("absolute left-0 top-0 grid size-6 place-items-center rounded-full text-xs font-semibold", st.kind === "verify" ? "bg-good/15 text-good" : "bg-accent text-accent-foreground")}>
              {st.kind === "verify" ? <ShieldCheck className="size-3.5" aria-label="Verify" /> : i + 1}
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <h4 className="text-sm font-semibold leading-6">{st.title}</h4>
              {st.kind === "verify" && <Badge tone="good">Verify</Badge>}
            </div>
            <p className="mt-1 text-sm text-muted-foreground">{fillPlaceholders(st.text, provider, values)}</p>
            {st.code && <div className="mt-2"><CodeBlock code={fillPlaceholders(st.code, provider, values)} label={st.title} /></div>}
            {link && (link.startsWith("/")
              ? <Link to={link} className="mt-2 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">{st.link_label || "Open"} <ArrowRight className="size-3.5" /></Link>
              : <a href={link} target="_blank" rel="noopener noreferrer" className="mt-2 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">{st.link_label || "Open"} <ExternalLink className="size-3.5" /></a>)}
          </li>
        );
      })}
    </ol>
  );
}

function ConnectDialog({ connect, setConnect, provider, saving, onSave }: { connect: any; setConnect: (c: any) => void; provider: any; saving: boolean; onSave: () => void }) {
  const [results, setResults] = useState<any[] | null>(null);
  const test = useAction(() => api<{ results: any[] }>("/integrations/test", { body: { provider: connect.id ? null : connect.provider, integration_id: connect.id ?? null, values: connect.values } }), { invalidate: [], onSuccess: (r) => setResults(r.results) });
  const setValue = (name: string, v: string) => { setConnect({ ...connect, values: { ...connect.values, [name]: v } }); setResults(null); };
  if (!provider) return null;
  return (
    <Dialog open onOpenChange={(o) => !o && setConnect(null)} extraWide title={connect.id ? `Edit ${connect.name}` : `Connect ${provider.name}`}
      description="Use credentials with read-only permissions only. Secrets are encrypted and can never be read back; leave a secret empty to keep the stored one."
      footer={<><Button variant="outline" loading={test.isPending} onClick={() => test.mutate(undefined)}><FlaskConical /> Test connection</Button><Button loading={saving} onClick={onSave}>Save</Button></>}>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
        <section aria-label="Setup guide">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Setup guide</h3>
          <SetupGuide provider={provider} values={connect.values} />
        </section>
        <section className="space-y-4 lg:border-l lg:pl-6" aria-label="Settings">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Settings</h3>
          <Field label="Name"><Input value={connect.name} onChange={(e) => setConnect({ ...connect, name: e.target.value })} /></Field>
          {provider.fields.map((f: any) => (
            <Field key={f.name} label={f.label} hint={f.help}>{f.options?.length
              ? <Select value={connect.values[f.name] ?? ""} onChange={(v) => setValue(f.name, v ?? "")} ariaLabel={f.label}
                  allowEmpty={f.options.some(([v]: [string, string]) => v === "")} emptyLabel={f.options.find(([v]: [string, string]) => v === "")?.[1]}
                  options={f.options.filter(([v]: [string, string]) => v !== "").map(([v, l]: [string, string]) => ({ value: v, label: l }))} />
              : <Input type={f.secret ? "password" : "text"} autoComplete="off" placeholder={f.secret && connect.id ? "•••••••• (stored)" : ""} value={connect.values[f.name] ?? ""} onChange={(e) => setValue(f.name, e.target.value)} />}</Field>
          ))}
          <Field label="Run every (hours)"><Input type="number" min={1} max={720} value={connect.schedule_hours} onChange={(e) => setConnect({ ...connect, schedule_hours: Number(e.target.value) })} /></Field>
          <Field label="Key or secret expires on" hint="Optional. You're reminded two weeks before, so the integration doesn't stop without warning.">
            <DateInput ariaLabel="Key or secret expires on" value={connect.credential_expires_on ?? null} onChange={(v) => setConnect({ ...connect, credential_expires_on: v })} />
          </Field>
          <div className="rounded-lg border bg-muted/30 p-3" aria-live="polite">
            <div className="text-sm font-medium">Test connection</div>
            <p className="mt-0.5 text-xs text-muted-foreground">{provider.inventory ? "Reads one page from each source with these settings and shows what it found. Nothing is saved." : "Runs the checks now with these settings. Nothing is saved and no evidence is filed."}
              {provider.checks_permissions ? " It also asks the tool what the key is allowed to do, and warns if it can change anything." : " Check the key's permissions with the guide's last step."}</p>
            {provider.inventory && provider.mapping_note && <p className="mt-1 text-xs text-muted-foreground">Field mapping: {provider.mapping_note}</p>}
            {results && (
              <ul className="mt-3 space-y-2">{results.map((r) => (
                <li key={r.check_key} className="text-sm">
                  <div className="flex items-start justify-between gap-2"><span className="font-medium">{r.title}</span><StatusBadge status={r.result} /></div>
                  <p className="text-xs text-muted-foreground">{r.summary}</p>
                  {r.fields && Object.keys(r.fields).length > 0 && (
                    <details className="mt-1 text-xs">
                      <summary className="cursor-pointer text-muted-foreground">Fields the API returned (names only)</summary>
                      <ul className="mt-1 space-y-1">{Object.entries(r.fields).map(([k, v]: any) => <li key={k}><span className="font-medium">{k}:</span> <span className="font-mono text-muted-foreground">{v.join(", ") || "(none)"}</span></li>)}</ul>
                    </details>
                  )}
                </li>
              ))}</ul>
            )}
          </div>
        </section>
      </div>
    </Dialog>
  );
}
