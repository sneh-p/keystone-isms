import { useState } from "react";
import { Link } from "react-router";
import { BadgeAlert, CheckCircle2, FileWarning, ShieldAlert, UserX } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, useUrlFilter } from "@/lib/hooks";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Textarea } from "@/components/ui/input";
import { Empty, KeyValue, PageHeader, Skeleton, Stat } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";

const SEVERITY = ["low", "medium", "high", "critical"].map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }));

/** Reports of suspicious activity from the employee portal, triaged by incident handlers (ISO 27001 A.6.8). */
export function SecurityReports() {
  const { data } = useApi<any>("/security-reports");
  const [open, setOpen] = useUrlFilter("open");
  if (!data) return <Skeleton className="h-96" />;
  const fresh = data.reports.filter((r: any) => r.status === "new");
  const current = open ? data.reports.find((r: any) => String(r.id) === open) : undefined;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={BadgeAlert} title="Security reports" description="What employees reported from the portal: suspicious emails, lost devices, odd behaviour. Open an incident from a report, or close it with a reply to the reporter." />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="Waiting for triage" value={fresh.length} tone={fresh.length ? "warning" : undefined} />
        <Stat label="Clicked or entered a password" value={fresh.filter((r: any) => r.clicked).length} tone={fresh.some((r: any) => r.clicked) ? "critical" : undefined} hint="Waiting, and urgent" />
        <Stat label="Became incidents" value={data.reports.filter((r: any) => r.status === "incident").length} />
        <Stat label="Reports in total" value={data.reports.length} />
      </div>
      <DataTable rows={data.reports} rowKey={(r: any) => r.id} onRowClick={(r: any) => setOpen(String(r.id))} exportName="security-reports" empty="No reports yet. Employees report from their portal."
        search={(r: any) => `${r.ref} ${r.description} ${r.sender ?? ""} ${r.subject ?? ""} ${r.reporter ?? ""}`}
        columns={[
          { key: "k", header: "Report", cell: (r: any) => <span><span className="font-medium">{data.kinds[r.kind]}</span><span className="block font-mono text-xs text-muted-foreground">{r.ref}</span></span> },
          { key: "d", header: "What happened", cell: (r: any) => <span className="line-clamp-2 text-sm">{r.description}</span> },
          { key: "r", header: "Reported by", cell: (r: any) => <span>{r.reporter}<span className="block text-xs text-muted-foreground">{fmtDate(r.created_at)}</span></span> },
          { key: "s", header: "Status", cell: (r: any) => (r.status === "new" ? <span className="flex flex-wrap gap-1"><Badge tone="primary">New</Badge>{r.clicked && <Badge tone="critical">Clicked</Badge>}</span> : <Badge tone={r.status === "incident" ? "warning" : "neutral"}>{data.outcomes[r.outcome] ?? r.status}</Badge>) },
        ]} />
      {current && <ReportPanel report={current} kinds={data.kinds} outcomes={data.outcomes} onClose={() => setOpen(null)} />}
    </div>
  );
}

function ReportPanel({ report: r, kinds, outcomes, onClose }: { report: any; kinds: Record<string, string>; outcomes: Record<string, string>; onClose: () => void }) {
  const [mode, setMode] = useState<"incident" | "close" | null>(null);
  const [severity, setSeverity] = useState<string | null>(r.clicked ? "high" : "medium");
  const [outcome, setOutcome] = useState<string | null>(r.kind === "phishing" ? "phishing_blocked" : "not_a_threat");
  const [reply, setReply] = useState("");
  const inv = ["/security-reports", "/incidents", "/dashboard"];
  const toIncident = useAction(() => api<any>(`/security-reports/${r.id}/incident`, { body: { severity, reply: reply || null } }), { success: (x: any) => `Incident ${x.ref} opened.`, invalidate: inv, onSuccess: () => setMode(null) });
  const close = useAction(() => api(`/security-reports/${r.id}/close`, { body: { outcome, reply } }), { success: "Report closed; the reporter sees your reply.", invalidate: inv, onSuccess: () => setMode(null) });
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={`${r.ref} · ${kinds[r.kind]}`} subtitle={`Reported by ${r.reporter} on ${fmtDate(r.created_at)}`}>
      <div className="space-y-6">
        {r.clicked && <p className="flex items-center gap-2 rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-sm"><ShieldAlert className="size-4 shrink-0" /> They clicked a link, opened an attachment or entered a password: act quickly (reset the password, check the device).</p>}
        <KeyValue items={[["What happened", <span key="d" className="whitespace-pre-wrap">{r.description}</span>], ["From", r.sender ?? "—"], ["Subject", r.subject ?? "—"], ["Where", r.where ?? "—"]]} />
        {r.status === "new" ? (
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => setMode("incident")}><FileWarning /> Open an incident</Button>
            <Button variant="outline" onClick={() => setMode("close")}><CheckCircle2 /> Close with a reply</Button>
          </div>
        ) : (
          <KeyValue items={[["Outcome", outcomes[r.outcome] ?? r.status], ["Reply to the reporter", r.reply ?? "—"], ["Triaged", `${r.triaged_by ?? ""} ${fmtDate(r.triaged_at)}`],
            ...(r.incident_id ? [["Incident", <Link key="i" to={`/incidents?open=${r.incident_id}`} className="text-primary underline">Open the incident</Link>] as [string, any]] : [])]} />
        )}
      </div>
      {mode && (
        <Dialog open onOpenChange={(o) => !o && setMode(null)} title={mode === "incident" ? "Open an incident" : "Close the report"}
          description="The reporter sees the outcome and your reply in their portal, not the incident itself."
          footer={mode === "incident"
            ? <Button disabled={!severity} loading={toIncident.isPending} onClick={() => toIncident.mutate(undefined)}>Open incident</Button>
            : <Button disabled={!outcome || !reply.trim()} loading={close.isPending} onClick={() => close.mutate(undefined)}>Close report</Button>}>
          <div className="space-y-4">
            {mode === "incident" ? <Field label="Severity" required><Select ariaLabel="Severity" value={severity} onChange={setSeverity} options={SEVERITY} /></Field>
              : <Field label="Outcome" required><Select ariaLabel="Outcome" value={outcome} onChange={setOutcome} options={["phishing_blocked", "not_a_threat", "duplicate"].map((k) => ({ value: k, label: outcomes[k] }))} /></Field>}
            <Field label={mode === "incident" ? "Reply to the reporter (optional)" : "Reply to the reporter"} required={mode === "close"} hint="Thank them: reports are how attacks are caught early.">
              <Textarea value={reply} maxLength={2000} onChange={(e) => setReply(e.target.value)} />
            </Field>
          </div>
        </Dialog>
      )}
    </Sheet>
  );
}

/** Leavers who keep access, and accounts with nobody behind them (ISO 27001 A.5.18, A.6.5). */
export function AccessCheck() {
  const { data } = useApi<any>("/access-check");
  const [exempting, setExempting] = useState<any>(null);
  const [note, setNote] = useState("");
  const inv = ["/access-check"];
  const exempt = useAction(() => api("/access-check/exemptions", { body: { account: exempting.key, note } }), { success: "Marked as expected.", invalidate: inv, onSuccess: () => { setExempting(null); setNote(""); } });
  const unexempt = useAction((id: number) => api(`/access-check/exemptions/${id}`, { method: "DELETE" }), { success: "It will be checked again.", invalidate: inv });
  if (!data) return <Skeleton className="h-96" />;
  const f = data.findings;
  const kinds: Record<string, string> = { leaver: "Leaver with access", orphan: "No person in People", guest: "Guest account" };
  return (
    <div className="animate-fade-in">
      <PageHeader icon={UserX} title="Leaver access check" description={`People compared with the accounts Keystone can see (${data.sources.join(", ")}): leavers who still have access, and accounts nobody in People owns. Nothing is changed here; deactivate accounts in Users or in the source system.`} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-3">
        <Stat label="Leavers with access" value={f.filter((x: any) => x.kind === "leaver").length} tone={f.some((x: any) => x.kind === "leaver") ? "critical" : "good"} />
        <Stat label="Guest accounts" value={f.filter((x: any) => x.kind === "guest").length} />
        <Stat label="Accounts with no person" value={f.filter((x: any) => x.kind === "orphan").length} />
      </div>
      {f.length === 0 ? <Empty icon={CheckCircle2} title="Nothing to fix">Every leaver's accounts are disabled, and every account belongs to someone in People.</Empty> : (
        <DataTable rows={f} rowKey={(x: any) => `${x.kind}-${x.source}-${x.account}`} exportName="leaver-access-check" search={(x: any) => `${x.account} ${x.person ?? ""} ${x.source}`}
          columns={[
            { key: "k", header: "Finding", cell: (x: any) => <Badge tone={x.severity === "high" ? "critical" : x.severity === "medium" ? "warning" : "neutral"}>{kinds[x.kind]}</Badge> },
            { key: "a", header: "Account", cell: (x: any) => <span><span className="font-medium">{x.account}</span><span className="block text-xs text-muted-foreground">{x.source}</span></span> },
            { key: "d", header: "Detail", cell: (x: any) => <span className="text-sm">{x.detail}</span> },
            { key: "x", header: "", cell: (x: any) => (
              <span className="flex justify-end gap-2">
                <Link to={x.page} className="text-sm text-primary hover:underline">Open</Link>
                {x.key && <Button size="sm" variant="ghost" onClick={() => setExempting(x)}>Expected</Button>}
              </span>
            ) },
          ]} />
      )}
      {data.exemptions.length > 0 && (
        <div className="mt-8">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">Expected accounts</h2>
          <DataTable rows={data.exemptions} rowKey={(x: any) => x.id} columns={[
            { key: "a", header: "Account", cell: (x: any) => x.account },
            { key: "n", header: "Why", cell: (x: any) => x.note },
            { key: "w", header: "Since", cell: (x: any) => fmtDate(x.created_at) },
            { key: "x", header: "", cell: (x: any) => <Button size="sm" variant="ghost" onClick={() => unexempt.mutate(x.id)}>Check again</Button> },
          ]} />
        </div>
      )}
      {exempting && (
        <Dialog open onOpenChange={(o) => !o && setExempting(null)} title={`Expected: ${exempting.account}`} description="For service and shared accounts. It is no longer listed; the reason is recorded."
          footer={<Button disabled={!note.trim()} loading={exempt.isPending} onClick={() => exempt.mutate(undefined)}>Mark as expected</Button>}>
          <Field label="Why this account has no person" required><Textarea value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Backup service account, owned by IT operations" /></Field>
        </Dialog>
      )}
    </div>
  );
}

const STATE: Record<string, [string, string]> = { expired: ["Expired", "critical"], ending: ["Ends within 30 days", "warning"], requested: ["Requested", "primary"], active: ["Active", "good"], no_end: ["No end date", "warning"] };

/** Every exception in force, wherever it was granted (ISO 27001 A.5.36, 6.1.3). */
export function Exceptions() {
  const { data } = useApi<any[]>("/exceptions");
  const [type, setType] = useState<string | null>(null);
  if (!data) return <Skeleton className="h-96" />;
  const types = [...new Map(data.map((x) => [x.type, x.type_label.replace(" (requested)", "")])).entries()].map(([value, label]) => ({ value, label }));
  const rows = type ? data.filter((x) => x.type === type) : data;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={FileWarning} title="Exceptions" description="Every exception in force in one place: risk acceptances, attack surface and configuration exceptions, and policy exceptions, with who approved them and when they end."
        actions={<Link to="/registers/policy-exceptions"><Button variant="outline">Policy exceptions</Button></Link>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="In force" value={data.filter((x) => ["active", "ending", "no_end"].includes(x.state)).length} />
        <Stat label="Ending within 30 days" value={data.filter((x) => x.state === "ending").length} tone={data.some((x) => x.state === "ending") ? "warning" : undefined} />
        <Stat label="Expired, still recorded" value={data.filter((x) => x.state === "expired").length} tone={data.some((x) => x.state === "expired") ? "critical" : undefined} />
        <Stat label="Waiting for a decision" value={data.filter((x) => x.state === "requested").length} />
      </div>
      <DataTable rows={rows} rowKey={(x: any) => `${x.type}-${x.page}-${x.title}`} exportName="exceptions" empty="No exceptions." search={(x: any) => `${x.ref} ${x.title} ${x.reason ?? ""} ${x.approved_by ?? ""}`}
        toolbar={<div className="w-56"><Select ariaLabel="Kind of exception" value={type} onChange={setType} allowEmpty emptyLabel="All kinds" options={types} /></div>}
        columns={[
          { key: "t", header: "Exception", cell: (x: any) => <Link to={x.page} className="hover:underline"><span className="font-medium">{x.title}</span><span className="block text-xs text-muted-foreground">{x.type_label}{x.ref ? ` · ${x.ref}` : ""}</span></Link> },
          { key: "r", header: "Reason", cell: (x: any) => <span className="line-clamp-2 text-sm">{x.reason ?? "—"}</span> },
          { key: "b", header: "Approved by", cell: (x: any) => x.approved_by ?? "—" },
          { key: "u", header: "Ends", cell: (x: any) => (x.until ? fmtDate(x.until) : "—") },
          { key: "s", header: "State", cell: (x: any) => <Badge tone={STATE[x.state][1] as any}>{STATE[x.state][0]}</Badge> },
        ]} />
    </div>
  );
}
