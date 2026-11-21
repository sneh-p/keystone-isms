import { useEffect, useState } from "react";
import { Link } from "react-router";
import { AlertTriangle, Fish, Globe, Mail, PhoneCall, Play, Plus, RefreshCw, ShieldAlert, Square, Upload } from "lucide-react";
import { api, upload } from "@/lib/api";
import { useAction, useApi, usePeople, useUrlFilter } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, KeyValue, PageHeader, Section, Skeleton, Stat } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { Tabs } from "@/components/ui/tabs";
import { DateInput } from "@/components/forms";
import { AudienceEditor, audienceText, type Audience } from "@/components/Training";

const CAMPAIGN_STATUS: Record<string, [string, string]> = { draft: ["Draft", "primary"], running: ["Running", "warning"], completed: ["Completed", "good"], cancelled: ["Cancelled", "neutral"] };

// ---- phishing simulations --------------------------------------------------------------------------------------------

/** Practice phishing emails to staff (ISO 27001 A.6.3): who clicks, who reports. */
export function PhishingSimulations() {
  const { me } = useAuth();
  const { data } = useApi<any>("/phishing");
  const [open, setOpen] = useUrlFilter("open");
  const [form, setForm] = useState<{ name: string; template: string | null; audience: Audience } | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const inv = ["/phishing"];
  const create = useAction(() => api<any>("/phishing", { body: form }), { success: "Campaign prepared. Someone else launches it.", invalidate: inv, onSuccess: (c: any) => { setForm(null); setOpen(String(c.id)); } });
  if (!data) return <Skeleton className="h-96" />;
  const current = open ? data.campaigns.find((c: any) => String(c.id) === open) : undefined;
  const done = data.campaigns.filter((c: any) => c.status === "completed");
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Fish} title="Phishing simulations" description="Practice phishing emails, sent through your own email relay to the people you choose. Anyone who clicks lands on a page explaining the warning signs; it never asks for anything. Reporting the email from the portal counts as catching it."
        actions={<Button onClick={() => setForm({ name: "", template: null, audience: null })}><Plus /> New campaign</Button>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="Campaigns run" value={done.length} />
        <Stat label="Latest click rate" value={done[0] ? `${done[0].results.click_rate}%` : "—"} tone={done[0] && done[0].results.click_rate > 10 ? "warning" : undefined} hint="Lower is better" />
        <Stat label="Latest report rate" value={done[0] ? `${done[0].results.report_rate}%` : "—"} hint="Higher is better" />
        <Stat label="Running now" value={data.campaigns.filter((c: any) => c.status === "running").length} />
      </div>
      <DataTable rows={data.campaigns} rowKey={(c: any) => c.id} onRowClick={(c: any) => setOpen(String(c.id))} exportName="phishing-campaigns" empty="No campaigns yet."
        columns={[
          { key: "n", header: "Campaign", cell: (c: any) => <span><span className="font-medium">{c.name}</span><span className="block text-xs text-muted-foreground">{data.templates[c.template]?.title} · {audienceText(c.audience)}</span></span> },
          { key: "s", header: "Sent", cell: (c: any) => <span className="tabular-nums">{c.results.sent} of {c.results.targets}</span> },
          { key: "c", header: "Clicked", cell: (c: any) => <span className="tabular-nums">{c.results.click_rate}%</span> },
          { key: "r", header: "Reported", cell: (c: any) => <span className="tabular-nums">{c.results.report_rate}%</span> },
          { key: "st", header: "Status", cell: (c: any) => <Badge tone={CAMPAIGN_STATUS[c.status][1] as any}>{CAMPAIGN_STATUS[c.status][0]}</Badge> },
        ]} />
      <div className="mt-6" />
      <Section title="Templates" level={2}>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Object.entries(data.templates).map(([k, t]: any) => (
            <button key={k} type="button" onClick={() => setPreview(k)} className="rounded-lg border bg-card p-3 text-left hover:bg-muted/50">
              <span className="block font-medium">{t.title}</span><span className="block text-xs text-muted-foreground">{t.difficulty} · from "{t.from_name}"</span>
            </button>
          ))}
        </div>
      </Section>
      {preview && (
        <Dialog open onOpenChange={(o) => !o && setPreview(null)} wide title={data.templates[preview].title} description={`From "${data.templates[preview].from_name}" · ${data.templates[preview].subject}`}>
          <pre className="whitespace-pre-wrap rounded-md border bg-muted/40 p-3 font-sans text-sm">{data.templates[preview].body.replace("{link}", "[practice link]")}</pre>
          <p className="mt-3 text-sm font-medium">What people should notice</p>
          <ul className="mt-1 list-disc pl-5 text-sm text-muted-foreground">{data.templates[preview].red_flags.map((f: string) => <li key={f}>{f}</li>)}</ul>
        </Dialog>
      )}
      {form && (
        <Dialog open onOpenChange={(o) => !o && setForm(null)} wide title="New campaign" description="Prepare it here; someone other than you launches it. Email must be set up, and KEYSTONE_PUBLIC_URL set."
          footer={<Button disabled={!form.name.trim() || !form.template} loading={create.isPending} onClick={() => create.mutate(undefined)}>Prepare campaign</Button>}>
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name" required><Input value={form.name} maxLength={200} onChange={(e) => setForm((f) => f && { ...f, name: e.target.value })} placeholder="e.g. Q1 practice" /></Field>
              <Field label="Template" required><Select ariaLabel="Template" value={form.template} onChange={(v) => setForm((f) => f && { ...f, template: v })} options={Object.entries(data.templates).map(([value, t]: any) => ({ value, label: `${t.title} (${t.difficulty})` }))} /></Field>
            </div>
            <AudienceEditor value={form.audience} onChange={(audience) => setForm((f) => f && { ...f, audience })} />
          </div>
        </Dialog>
      )}
      {current && <CampaignPanel c={current} me={me?.id} templates={data.templates} onClose={() => setOpen(null)} />}
    </div>
  );
}

function CampaignPanel({ c, me, templates, onClose }: { c: any; me?: number; templates: any; onClose: () => void }) {
  const inv = ["/phishing"];
  const launch = useAction(() => api(`/phishing/${c.id}/launch`, { method: "POST" }), { success: "Launched: emails go out over the next minutes.", invalidate: inv });
  const complete = useAction(() => api(`/phishing/${c.id}/complete`, { method: "POST" }), { success: "Campaign ended.", invalidate: inv });
  const r = c.results;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={c.name} subtitle={`${templates[c.template]?.title} · ${audienceText(c.audience)} · ${CAMPAIGN_STATUS[c.status][0]}`}
      actions={<>
        {c.status === "draft" && (c.created_by_id === me ? <span className="text-xs text-muted-foreground">Someone else launches it</span>
          : <Button size="sm" loading={launch.isPending} onClick={() => { if (window.confirm("Send the practice email to everyone in this audience?")) launch.mutate(undefined); }}><Play /> Launch</Button>)}
        {["draft", "running"].includes(c.status) && <Button size="sm" variant="outline" loading={complete.isPending} onClick={() => complete.mutate(undefined)}><Square /> {c.status === "draft" ? "Cancel" : "End now"}</Button>}
      </>}>
      <div className="space-y-6">
        <div className="grid grid-cols-3 gap-3">
          <Stat label="Sent" value={`${r.sent} of ${r.targets}`} />
          <Stat label="Clicked" value={`${r.click_rate}%`} hint={`${r.clicked} people`} tone={r.click_rate > 10 ? "warning" : undefined} />
          <Stat label="Reported" value={`${r.report_rate}%`} hint={`${r.reported} people`} tone={r.report_rate >= 50 ? "good" : undefined} />
        </div>
        {r.by_department.length > 0 && (
          <Section title="By department" level={3}>
            <DataTable rows={r.by_department} rowKey={(d: any) => d.department} columns={[
              { key: "d", header: "Department", cell: (d: any) => d.department },
              { key: "s", header: "Sent", cell: (d: any) => d.sent },
              { key: "c", header: "Clicked", cell: (d: any) => d.clicked },
              { key: "r", header: "Reported", cell: (d: any) => d.reported },
            ]} />
          </Section>
        )}
        {r.people.length > 0 && (
          <Section title="People (need-to-know)" level={3}>
            <p className="mb-2 text-xs text-muted-foreground">Use individual results for support and training, not blame.</p>
            <DataTable rows={r.people} rowKey={(p: any) => `${p.name}-${p.sent_at}`} search={(p: any) => `${p.name} ${p.department ?? ""}`} columns={[
              { key: "n", header: "Person", cell: (p: any) => <span>{p.name}<span className="block text-xs text-muted-foreground">{p.department ?? ""}</span></span> },
              { key: "s", header: "Sent", cell: (p: any) => (p.error ? <span className="text-critical">{p.error}</span> : p.sent_at ? fmtDate(p.sent_at) : "Waiting") },
              { key: "c", header: "Clicked", cell: (p: any) => (p.clicked_at ? <Badge tone="warning">Clicked</Badge> : "—") },
              { key: "r", header: "Reported", cell: (p: any) => (p.reported_at ? <Badge tone="good">Reported</Badge> : "—") },
            ]} />
          </Section>
        )}
      </div>
    </Sheet>
  );
}

/** Where a practice email's link lands (public: opened from the email, signed in or not). Never asks for anything. */
export function PhishLanding() {
  const [state, setState] = useState<{ ok: boolean; data?: any }>({ ok: false });
  useEffect(() => {
    const token = new URLSearchParams(window.location.hash.slice(1)).get("t");
    if (!token) { setState({ ok: true }); return; }
    api<any>("/public/phish", { body: { token } }).then((d) => setState({ ok: true, data: d }), () => setState({ ok: true }));
    history.replaceState(null, "", window.location.pathname);  // the token doesn't stay in the address bar
  }, []);
  return (
    <main className="grid min-h-full place-items-center bg-muted/30 p-6">
      <div className="w-full max-w-xl rounded-xl border bg-card p-6 shadow-card sm:p-8">
        <ShieldAlert className="size-10 text-primary" aria-hidden />
        <h1 className="mt-3 text-2xl font-semibold">This was a practice phishing email</h1>
        <p className="mt-2 text-muted-foreground">It came from your security team, to help everyone spot the real thing. Nothing happened and nothing was collected. Nobody is in trouble.</p>
        {state.data && (
          <>
            <p className="mt-5 text-sm font-medium">The email: "{state.data.subject}"</p>
            <p className="mt-3 text-sm font-medium">What could have given it away</p>
            <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">{state.data.red_flags.map((f: string) => <li key={f}>{f}</li>)}</ul>
          </>
        )}
        <p className="mt-5 text-sm">Next time something looks odd, don't click: report it from your employee portal (<span className="font-medium">Report something suspicious</span>). Reporting quickly is what stops real attacks.</p>
      </div>
    </main>
  );
}

// ---- domain protection: look-alike domains and DMARC -----------------------------------------------------------------

const LOOK_TONE: Record<string, string> = { new: "warning", ours: "good", benign: "neutral", threat: "critical" };

export function DomainProtection() {
  const [tab, setTab] = useUrlFilter("tab");
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Globe} title="Domain protection" description="Look-alike domains registered to imitate yours, found in public certificate logs, and who sends email as your domains (DMARC reports)." />
      <Tabs tabs={[{ value: "lookalikes", label: "Look-alike domains", content: <Lookalikes /> }, { value: "dmarc", label: "DMARC reports", content: <Dmarc /> }]}
        value={tab ?? "lookalikes"} onValueChange={(v) => setTab(v === "lookalikes" ? null : v)} />
    </div>
  );
}

function Lookalikes() {
  const { can } = useAuth();
  const { data } = useApi<any>("/lookalikes");
  const [deciding, setDeciding] = useState<any>(null);
  const inv = ["/lookalikes"];
  const scan = useAction(() => api<any>("/lookalikes/scan", { method: "POST" }), { success: (r: any) => `${r.new} new look-alike domain(s).`, invalidate: inv });
  const decide = useAction(() => api(`/lookalikes/${deciding.id}/decide`, { body: { status: deciding.status, note: deciding.note || null } }), { success: "Saved.", invalidate: inv, onSuccess: () => setDeciding(null) });
  if (!data) return <Skeleton className="h-64" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-3xl text-sm text-muted-foreground">Checked every day for each verified domain (Attack surface → Internet-facing): certificates issued for names that contain your name, or are one or two typing mistakes away from it. Only your domain names are looked up.</p>
        {can("integration.manage") && <Button variant="outline" loading={scan.isPending} onClick={() => scan.mutate(undefined)}><RefreshCw /> Check now</Button>}
      </div>
      <DataTable rows={data.lookalikes} rowKey={(x: any) => x.id} exportName="lookalike-domains" empty="No look-alike domains found." search={(x: any) => x.name}
        columns={[
          { key: "n", header: "Domain", cell: (x: any) => <span><span className="font-mono text-sm">{x.name}</span><span className="block text-xs text-muted-foreground">{x.reason}</span></span> },
          { key: "f", header: "First seen", cell: (x: any) => fmtDate(x.first_seen) },
          { key: "s", header: "Status", cell: (x: any) => <Badge tone={LOOK_TONE[x.status] as any}>{x.status === "new" ? "New" : data.statuses[x.status]}</Badge> },
          { key: "note", header: "Note", cell: (x: any) => <span className="text-sm text-muted-foreground">{x.note ?? ""}</span> },
          { key: "x", header: "", cell: (x: any) => (can("integration.manage") ? <Button size="sm" variant="ghost" onClick={() => setDeciding({ ...x, status: x.status === "new" ? null : x.status })}>Decide</Button> : null) },
        ]} />
      {deciding && (
        <Dialog open onOpenChange={(o) => !o && setDeciding(null)} title={deciding.name} footer={<Button disabled={!deciding.status || (deciding.status === "threat" && !deciding.note?.trim())} loading={decide.isPending} onClick={() => decide.mutate(undefined)}>Save</Button>}>
          <div className="space-y-4">
            <Field label="This domain is" required><Select ariaLabel="This domain is" value={deciding.status} onChange={(v) => setDeciding((d: any) => ({ ...d, status: v }))} options={Object.entries(data.statuses).map(([value, label]) => ({ value, label: label as string }))} /></Field>
            <Field label="Note" required={deciding.status === "threat"} hint="For a threat: what is being done (blocked in email and web filters, takedown requested, ...)."><Textarea value={deciding.note ?? ""} maxLength={2000} onChange={(e) => setDeciding((d: any) => ({ ...d, note: e.target.value }))} /></Field>
          </div>
        </Dialog>
      )}
    </div>
  );
}

function Dmarc() {
  const { can } = useAuth();
  const { data } = useApi<any>("/dmarc");
  const [file, setFile] = useState<File | null>(null);
  const send = useAction(() => { const fd = new FormData(); fd.append("file", file!); return upload<any>("/dmarc", fd); },
    { success: (r: any) => `${r.added} report(s) added${r.already_had ? `, ${r.already_had} already had` : ""}.`, invalidate: ["/dmarc"], onSuccess: () => setFile(null) });
  if (!data) return <Skeleton className="h-64" />;
  const failing = data.sources.filter((s: any) => s.passed < s.messages);
  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-sm text-muted-foreground">Mail providers send DMARC aggregate reports to the address in your DMARC record (rua=). Upload them here (.xml, .xml.gz or .zip, up to 10 MB). Only the figures are kept, not the file.</p>
      {can("integration.manage") && (
        <div className="flex flex-wrap items-end gap-2 rounded-lg border p-3">
          <Field label="Report file"><input type="file" accept=".xml,.gz,.zip" aria-label="Report file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" /></Field>
          <Button disabled={!file} loading={send.isPending} onClick={() => send.mutate(undefined)}><Upload /> Upload</Button>
        </div>
      )}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="Messages (90 days)" value={data.messages} />
        <Stat label="Passed DMARC" value={data.messages ? `${Math.round((100 * data.passed) / data.messages)}%` : "—"} tone={data.messages && data.passed < data.messages ? "warning" : undefined} />
        <Stat label="Sources failing" value={failing.length} tone={failing.length ? "critical" : undefined} hint="Spoofing, or a service not set up for your domain" />
        <Stat label="Reports" value={data.count} />
      </div>
      {data.sources.length === 0 ? <Empty icon={Mail} title="No reports yet">Upload a DMARC aggregate report to see who sends email as your domains.</Empty> : (
        <DataTable rows={data.sources} rowKey={(s: any) => `${s.source_ip}-${s.header_from}`} exportName="dmarc-sources" search={(s: any) => `${s.source_ip} ${s.header_from ?? ""}`}
          columns={[
            { key: "ip", header: "Sending source", cell: (s: any) => <span><span className="font-mono text-sm">{s.source_ip}</span><span className="block text-xs text-muted-foreground">as {s.header_from ?? "—"}</span></span> },
            { key: "m", header: "Messages", cell: (s: any) => <span className="tabular-nums">{s.messages}</span> },
            { key: "p", header: "Passed", cell: (s: any) => <span className="tabular-nums">{s.passed}</span> },
            { key: "q", header: "Quarantined or rejected", cell: (s: any) => <span className="tabular-nums">{s.quarantined_or_rejected}</span> },
            { key: "s", header: "", cell: (s: any) => (s.passed < s.messages ? <Badge tone="critical"><AlertTriangle className="size-3" /> Failing</Badge> : <Badge tone="good">Passing</Badge>) },
          ]} />
      )}
    </div>
  );
}

// ---- supplier breach news -----------------------------------------------------------------------------------------

const BREACH_TONE: Record<string, string> = { new: "warning", not_affected: "good", assessing: "primary", affected: "critical" };

/** Public breach reports matched against your vendors' web addresses (A.5.19 to A.5.22). */
export function VendorBreaches() {
  const { can } = useAuth();
  const { data } = useApi<any>("/vendor-breaches");
  const [open, setOpen] = useState<any>(null);
  const inv = ["/vendor-breaches"];
  const scan = useAction(() => api<any>("/vendor-breaches/scan", { method: "POST" }), { success: (r: any) => `${r.new} new match(es).`, invalidate: inv });
  const decide = useAction(() => api(`/vendor-breaches/${open.id}/decide`, { body: { status: open.status, note: open.note } }), { success: "Saved.", invalidate: inv, onSuccess: () => setOpen(null) });
  if (!data) return <Skeleton className="h-64" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ShieldAlert} title="Supplier breach news" description="Breaches reported publicly (Have I Been Pwned) at your vendors, matched by their web address. The whole list is downloaded once a day and matched here: nobody learns who your vendors are."
        actions={can("vendor.write") && <Button variant="outline" loading={scan.isPending} onClick={() => scan.mutate(undefined)}><RefreshCw /> Check now</Button>} />
      <DataTable rows={data.breaches} rowKey={(b: any) => b.id} onRowClick={can("vendor.write") ? (b: any) => setOpen({ ...b, status: b.status === "new" ? null : b.status, note: b.note ?? "" }) : undefined}
        exportName="supplier-breaches" empty="No breaches reported at your vendors." search={(b: any) => `${b.vendor} ${b.title}`}
        columns={[
          { key: "v", header: "Vendor", cell: (b: any) => <span><span className="font-medium">{b.vendor}</span><span className="block text-xs text-muted-foreground">{b.title} · {b.domain}</span></span> },
          { key: "d", header: "Breach date", cell: (b: any) => (b.breach_date ? fmtDate(b.breach_date) : "—") },
          { key: "a", header: "Reported", cell: (b: any) => (b.added_on ? fmtDate(b.added_on) : "—") },
          { key: "c", header: "Data exposed", cell: (b: any) => <span className="text-sm">{(b.data_classes ?? []).slice(0, 4).join(", ")}{(b.data_classes ?? []).length > 4 ? "…" : ""}</span> },
          { key: "s", header: "Status", cell: (b: any) => <Badge tone={BREACH_TONE[b.status] as any}>{b.status === "new" ? "New" : data.statuses[b.status]}</Badge> },
        ]} />
      {open && (
        <Dialog open onOpenChange={(o) => !o && setOpen(null)} title={`${open.vendor}: ${open.title}`} description="Were you affected? Check with the vendor; assess the vendor again if so."
          footer={<Button disabled={!open.status || !open.note?.trim()} loading={decide.isPending} onClick={() => decide.mutate(undefined)}>Save</Button>}>
          <div className="space-y-4">
            <KeyValue items={[["Accounts", open.accounts?.toLocaleString() ?? "—"], ["Data exposed", (open.data_classes ?? []).join(", ") || "—"]]} />
            <Field label="Status" required><Select ariaLabel="Status" value={open.status} onChange={(v) => setOpen((o: any) => ({ ...o, status: v }))} options={Object.entries(data.statuses).map(([value, label]) => ({ value, label: label as string }))} /></Field>
            <Field label="Note" required><Textarea value={open.note} maxLength={2000} onChange={(e) => setOpen((o: any) => ({ ...o, note: e.target.value }))} /></Field>
            <Link to={`/vendors?open=${open.vendor_id}`} className="text-sm text-primary underline">Open the vendor</Link>
          </div>
        </Dialog>
      )}
    </div>
  );
}

// ---- on-call -------------------------------------------------------------------------------------------------------

/** Who is called first about critical incidents and alerts, and the escalation. */
export function OnCall() {
  const { can, me } = useAuth();
  const { people, name } = usePeople();
  const { data } = useApi<any>("/oncall");
  const [edit, setEdit] = useState<any>(null);
  const [focus] = useUrlFilter("page");
  const inv = ["/oncall"];
  const save = useAction(() => {
    const body = { name: edit.name, member_ids: edit.member_ids.map(Number), start_on: edit.start_on, rotation_days: Number(edit.rotation_days), escalate_after_minutes: Number(edit.escalate_after_minutes), active: edit.active !== false };
    return edit.id ? api(`/oncall/${edit.id}`, { method: "PUT", body }) : api("/oncall", { body });
  }, { success: "Rota saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  const ack = useAction((id: number) => api(`/oncall/pages/${id}/ack`, { method: "POST" }), { success: "Acknowledged: escalation stopped.", invalidate: inv });
  if (!data) return <Skeleton className="h-64" />;
  const mine = (data.pages ?? []).filter((p: any) => p.user_id === me?.id && !p.acked_at);
  return (
    <div className="animate-fade-in">
      <PageHeader icon={PhoneCall} title="On-call" description="Critical incidents and critical alerts page whoever is on call: in Keystone and by email straight away, and on your chat channels. If nobody acknowledges in time, the next person is paged, then the ISMS managers."
        actions={can("org.write") && <Button onClick={() => setEdit({ name: "", member_ids: [], start_on: new Date().toISOString().slice(0, 10), rotation_days: 7, escalate_after_minutes: 15 })}><Plus /> New rota</Button>} />
      {mine.length > 0 && (
        <div className="mb-5 space-y-2">
          {mine.map((p: any) => (
            <div key={p.id} className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border border-critical/40 bg-critical/10 px-4 py-3 ${String(p.id) === focus ? "ring-2 ring-critical" : ""}`}>
              <span className="text-sm"><span className="font-medium">{p.title}</span> <span className="text-muted-foreground">· {fmtDate(p.created_at)}</span></span>
              <span className="flex gap-2"><Link to={p.page}><Button size="sm" variant="outline">Open</Button></Link><Button size="sm" loading={ack.isPending} onClick={() => ack.mutate(p.id)}>Acknowledge</Button></span>
            </div>
          ))}
        </div>
      )}
      {data.rotas.length === 0 ? <Empty icon={PhoneCall} title="No on-call rota yet">Add the people who handle incidents, in rotation order.</Empty> : (
        <DataTable rows={data.rotas} rowKey={(r: any) => r.id} onRowClick={can("org.write") ? (r: any) => setEdit({ ...r, member_ids: r.member_ids.map(String) }) : undefined} columns={[
          { key: "n", header: "Rota", cell: (r: any) => <span className={r.active ? undefined : "opacity-60"}><span className="font-medium">{r.name}</span><span className="block text-xs text-muted-foreground">Rotates every {r.rotation_days} day(s) · escalates after {r.escalate_after_minutes} min</span></span> },
          { key: "o", header: "On call now", cell: (r: any) => <span className="font-medium">{r.on_call ? name(r.on_call) : "—"}</span> },
          { key: "x", header: "Next", cell: (r: any) => (r.next ? name(r.next) : "—") },
          { key: "m", header: "Members", cell: (r: any) => r.member_ids.map((id: number) => name(id)).join(", ") },
        ]} />
      )}
      {data.pages && data.pages.length > 0 && (
        <div className="mt-6"><Section title="Recent pages" level={2}>
          <DataTable rows={data.pages} rowKey={(p: any) => p.id} columns={[
            { key: "t", header: "Call", cell: (p: any) => <Link to={p.page} className="hover:underline">{p.title}</Link> },
            { key: "u", header: "Paged", cell: (p: any) => `${name(p.user_id)}${p.level ? ` (escalation ${p.level})` : ""}` },
            { key: "w", header: "When", cell: (p: any) => fmtDate(p.created_at) },
            { key: "e", header: "Email", cell: (p: any) => (p.emailed ? "Sent" : "Not sent") },
            { key: "a", header: "Acknowledged", cell: (p: any) => (p.acked_at ? <Badge tone="good">Yes</Badge> : p.escalated_at ? <Badge tone="warning">Escalated</Badge> : <Badge tone="critical">Waiting</Badge>) },
          ]} />
        </Section></div>
      )}
      {edit && (
        <Dialog open onOpenChange={(o) => !o && setEdit(null)} wide title={edit.id ? `Edit: ${edit.name}` : "New on-call rota"}
          footer={<Button disabled={!edit.name.trim() || !edit.member_ids.length || !edit.start_on} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" required className="sm:col-span-2"><Input value={edit.name} maxLength={100} onChange={(e) => setEdit((x: any) => ({ ...x, name: e.target.value }))} placeholder="e.g. Security on-call" /></Field>
            <Field label="Members, in rotation order" required hint="People who can handle incidents." className="sm:col-span-2">
              <MultiSelect value={edit.member_ids} onChange={(v) => setEdit((x: any) => ({ ...x, member_ids: v }))} options={people.map((p) => ({ value: String(p.id), label: p.display_name }))} placeholder="Choose people" />
            </Field>
            <Field label="First person starts on" required><DateInput ariaLabel="First person starts on" value={edit.start_on} onChange={(v) => setEdit((x: any) => ({ ...x, start_on: v }))} /></Field>
            <Field label="Rotate every (days)"><Input type="number" min={1} max={31} value={edit.rotation_days} onChange={(e) => setEdit((x: any) => ({ ...x, rotation_days: e.target.value }))} /></Field>
            <Field label="Escalate after (minutes)"><Input type="number" min={5} max={240} value={edit.escalate_after_minutes} onChange={(e) => setEdit((x: any) => ({ ...x, escalate_after_minutes: e.target.value }))} /></Field>
          </div>
        </Dialog>
      )}
    </div>
  );
}
