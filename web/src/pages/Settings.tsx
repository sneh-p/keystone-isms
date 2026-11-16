import { useEffect, useState } from "react";
import { AlertOctagon, Building2, CheckCircle2, Download, KeyRound, Plus, ShieldAlert, Sparkles, Stamp, Trash2, UserCog, Activity, Mail } from "lucide-react";
import { api, downloadUrl } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { KeyValue, PageHeader, Skeleton, Switch } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { clean, DateInput, EnumSelect, OwnerSelect } from "@/components/forms";
import { DigestPreference } from "@/components/NotificationBell";
import { CopyButton } from "@/components/CopyButton";

export function Organisation() {
  const { can } = useAuth();
  const { name } = usePeople();
  const { data, isLoading } = useApi<any>("/org");
  const parties = useApi<any[]>("/org/parties");
  const roles = useApi<any[]>("/org/roles");
  const objectives = useApi<any[]>("/org/objectives");
  const [f, setF] = useState<any>(null);
  useEffect(() => { if (!isLoading) setF({ name: "", legal_name: "", industry: "", description: "", internal_issues: "", external_issues: "", risk_appetite: "", scope_statement: "", scope_inclusions: "", scope_exclusions: "", scope_interfaces: "", ...Object.fromEntries(Object.entries(data ?? {}).map(([k, v]) => [k, v ?? ""])) }); }, [data, isLoading]);
  const [party, setParty] = useState<any>(null);
  const [role, setRole] = useState<any>(null);
  const [obj, setObj] = useState<any>(null);
  const ed = can("org.write");
  const inv = ["/org", "/dashboard"];
  const save = useAction((b: any) => api("/org", { method: "PUT", body: b }), { success: "Saved.", invalidate: inv });
  const approve = useAction(() => api("/org/approve-scope", { method: "POST" }), { success: "Scope approved.", invalidate: inv });
  const addParty = useAction((b: any) => api("/org/parties", { body: b }), { success: "Added.", invalidate: ["/org"], onSuccess: () => setParty(null) });
  const delParty = useAction((id: number) => api(`/org/parties/${id}`, { method: "DELETE" }), { invalidate: ["/org"] });
  const addRole = useAction((b: any) => api("/org/roles", { body: b }), { success: "Added.", invalidate: ["/org"], onSuccess: () => setRole(null) });
  const delRole = useAction((id: number) => api(`/org/roles/${id}`, { method: "DELETE" }), { invalidate: ["/org"] });
  const saveObj = useAction((b: any) => (b.id ? api(`/org/objectives/${b.id}`, { method: "PATCH", body: clean({ ...b, id: undefined, ref: undefined }) }) : api("/org/objectives", { body: clean(b) })), { success: "Objective saved.", invalidate: ["/org"], onSuccess: () => setObj(null) });
  if (!f) return <Skeleton className="h-96" />;
  const t = (k: string, label: string, area = true) => <Field label={label}>{area ? <Textarea value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} disabled={!ed} /> : <Input value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} disabled={!ed} />}</Field>;
  const pick = (keys: string[]) => clean(Object.fromEntries(keys.map((k) => [k, f[k]])));
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Building2} title="Organisation & ISMS scope" description="Context, scope, interested parties, roles and objectives (ISO 27001 clauses 4 to 6)." />
      <Tabs tabs={[
        { value: "ctx", label: "Context (4.1)", content: <Card><CardBody className="grid gap-4 sm:grid-cols-2">
          {t("name", "Organisation name", false)}{t("legal_name", "Legal name", false)}{t("industry", "Industry", false)}<div />
          <div className="sm:col-span-2">{t("description", "Description")}</div>{t("internal_issues", "Internal issues")}{t("external_issues", "External issues")}
          <div className="sm:col-span-2">{t("risk_appetite", "Risk appetite statement")}</div>
          {ed && <div><Button loading={save.isPending} onClick={() => save.mutate(pick(["name", "legal_name", "industry", "description", "internal_issues", "external_issues", "risk_appetite"]))}>Save context</Button></div>}
        </CardBody></Card> },
        { value: "scope", label: "Scope (4.3)", content: <Card>
          <CardHeader title="ISMS scope" description={data?.scope_approved_at ? <span className="flex items-center gap-1 text-[#0a7a0a] dark:text-good"><CheckCircle2 className="size-4" /> Approved {fmtDate(data.scope_approved_at)} by {name(data.scope_approved_by_id)}</span> : "Not approved. Editing the scope clears any approval."}
            action={ed && !data?.scope_approved_at && f.scope_statement && <Button variant="outline" onClick={() => approve.mutate(undefined)}><Stamp /> Approve scope</Button>} />
          <CardBody className="space-y-4">{t("scope_statement", "Scope statement")}{t("scope_inclusions", "Inclusions (locations, units, systems)")}{t("scope_exclusions", "Exclusions and justification")}{t("scope_interfaces", "Interfaces and dependencies")}
            {ed && <Button loading={save.isPending} onClick={() => save.mutate(pick(["name", "scope_statement", "scope_inclusions", "scope_exclusions", "scope_interfaces"]))}>Save scope</Button>}
          </CardBody></Card> },
        { value: "parties", label: "Interested parties (4.2)", content: <>
          {ed && <Button className="mb-3" onClick={() => setParty({ name: "", party_type: "external", needs: "", addressed_by: "" })}><Plus /> Add</Button>}
          <DataTable rows={parties.data ?? []} rowKey={(p: any) => p.id} columns={[
            { key: "n", header: "Party", cell: (p: any) => <span className="font-medium">{p.name}</span> }, { key: "t", header: "Type", cell: (p: any) => titleCase(p.party_type) },
            { key: "ne", header: "Needs and expectations", cell: (p: any) => p.needs }, { key: "a", header: "How addressed", cell: (p: any) => p.addressed_by },
            { key: "x", header: "", cell: (p: any) => ed && <Button size="icon" variant="ghost" aria-label="Remove" onClick={() => delParty.mutate(p.id)}><Trash2 /></Button> },
          ]} />
        </> },
        { value: "roles", label: "ISMS roles (5.3)", content: <>
          {ed && <Button className="mb-3" onClick={() => setRole({ title: "", responsibilities: "", user_id: null, deputy_user_id: null })}><Plus /> Add role</Button>}
          <DataTable rows={roles.data ?? []} rowKey={(r: any) => r.id} columns={[
            { key: "t", header: "Role", cell: (r: any) => <span className="font-medium">{r.title}</span> }, { key: "h", header: "Holder", cell: (r: any) => name(r.user_id) }, { key: "d", header: "Deputy", cell: (r: any) => name(r.deputy_user_id) },
            { key: "r", header: "Responsibilities", cell: (r: any) => r.responsibilities }, { key: "x", header: "", cell: (r: any) => ed && <Button size="icon" variant="ghost" aria-label="Remove" onClick={() => delRole.mutate(r.id)}><Trash2 /></Button> },
          ]} />
        </> },
        { value: "obj", label: "Objectives (6.2)", content: <>
          {ed && <Button className="mb-3" onClick={() => setObj({ title: "", measure: "", target: "", current_value: "", owner_id: null, due_date: null, status: "on_track" })}><Plus /> Add objective</Button>}
          <DataTable rows={objectives.data ?? []} rowKey={(o: any) => o.id} onRowClick={ed ? (o: any) => setObj({ ...o }) : undefined} columns={[
            { key: "t", header: "Objective", cell: (o: any) => <div><div className="font-medium">{o.title}</div><div className="text-xs text-muted-foreground">{o.measure}</div></div> },
            { key: "p", header: "Current / target", cell: (o: any) => `${o.current_value ?? "—"} / ${o.target ?? "—"}` }, { key: "o", header: "Owner", cell: (o: any) => name(o.owner_id) },
            { key: "d", header: "Due", cell: (o: any) => fmtDate(o.due_date) },
            { key: "s", header: "Status", cell: (o: any) => <Badge tone={o.status === "achieved" ? "good" : o.status === "at_risk" ? "warning" : o.status === "missed" ? "critical" : "primary"}>{titleCase(o.status)}</Badge> },
          ]} />
        </> },
      ]} />
      <Dialog open={!!party} onOpenChange={(o) => !o && setParty(null)} title="Interested party" footer={<Button onClick={() => addParty.mutate(clean(party))}>Add</Button>}>
        {party && <div className="space-y-3"><Field label="Name"><Input value={party.name} onChange={(e) => setParty({ ...party, name: e.target.value })} /></Field><Field label="Type"><EnumSelect value={party.party_type} onChange={(v) => setParty({ ...party, party_type: v })} values={["external", "internal"]} /></Field><Field label="Needs and expectations"><Textarea value={party.needs} onChange={(e) => setParty({ ...party, needs: e.target.value })} /></Field><Field label="How the ISMS addresses them"><Textarea value={party.addressed_by} onChange={(e) => setParty({ ...party, addressed_by: e.target.value })} /></Field></div>}
      </Dialog>
      <Dialog open={!!role} onOpenChange={(o) => !o && setRole(null)} title="ISMS role" footer={<Button onClick={() => addRole.mutate(clean(role))}>Add</Button>}>
        {role && <div className="space-y-3"><Field label="Role title"><Input value={role.title} onChange={(e) => setRole({ ...role, title: e.target.value })} /></Field><Field label="Holder"><OwnerSelect value={role.user_id} onChange={(v) => setRole({ ...role, user_id: v })} /></Field><Field label="Deputy"><OwnerSelect value={role.deputy_user_id} onChange={(v) => setRole({ ...role, deputy_user_id: v })} /></Field><Field label="Responsibilities and authorities"><Textarea value={role.responsibilities} onChange={(e) => setRole({ ...role, responsibilities: e.target.value })} /></Field></div>}
      </Dialog>
      <Dialog open={!!obj} onOpenChange={(o) => !o && setObj(null)} title="Security objective" footer={<Button onClick={() => saveObj.mutate(obj)}>Save</Button>}>
        {obj && <div className="grid gap-3 sm:grid-cols-2"><Field label="Objective" className="sm:col-span-2"><Input value={obj.title} onChange={(e) => setObj({ ...obj, title: e.target.value })} /></Field><Field label="How it is measured" className="sm:col-span-2"><Input value={obj.measure ?? ""} onChange={(e) => setObj({ ...obj, measure: e.target.value })} /></Field><Field label="Target"><Input value={obj.target ?? ""} onChange={(e) => setObj({ ...obj, target: e.target.value })} /></Field><Field label="Current value"><Input value={obj.current_value ?? ""} onChange={(e) => setObj({ ...obj, current_value: e.target.value })} /></Field><Field label="Owner"><OwnerSelect value={obj.owner_id} onChange={(v) => setObj({ ...obj, owner_id: v })} /></Field><Field label="Due"><DateInput value={obj.due_date} onChange={(v) => setObj({ ...obj, due_date: v })} /></Field><Field label="Status"><EnumSelect value={obj.status} onChange={(v) => setObj({ ...obj, status: v })} values={["on_track", "at_risk", "achieved", "missed"]} /></Field></div>}
      </Dialog>
    </div>
  );
}

export function Users() {
  const { me } = useAuth();
  const { data } = useApi<any[]>("/users");
  const roles = useApi<any[]>("/roles");
  const [nu, setNu] = useState<any>(null);
  const [edit, setEdit] = useState<any>(null);
  const create = useAction((b: any) => api("/users", { body: b }), { success: "User created. They must change the temporary password at first sign-in.", invalidate: ["/users", "/people-directory"], onSuccess: () => setNu(null) });
  const update = useAction((b: any) => api(`/users/${b.id}`, { method: "PATCH", body: b.body }), { success: "User updated.", invalidate: ["/users", "/people-directory"], onSuccess: () => setExp(null) });
  const [exp, setExp] = useState<any>(null);
  const reset = useAction((b: any) => api(`/users/${b.id}/reset-password`, { body: { password: b.password } }), { success: "Password reset; their sessions were signed out.", invalidate: ["/users"], onSuccess: () => setEdit(null) });
  if (!data || !roles.data) return <Skeleton className="h-96" />;
  const ropts = roles.data.map((r) => ({ value: r.value, label: r.label }));
  const label = new Map(roles.data.map((r) => [r.value, r.label]));
  return (
    <div className="animate-fade-in">
      <PageHeader icon={UserCog} title="Users" description="Accounts and roles. Accounts are never deleted, so the audit trail stays intact." actions={<Button onClick={() => setNu({ username: "", display_name: "", email: "", role: "viewer", password: "" })}><Plus /> Add user</Button>} />
      <DataTable rows={data} rowKey={(u: any) => u.id} search={(u: any) => `${u.username} ${u.display_name}`} columns={[
        { key: "n", header: "User", cell: (u: any) => <div><div className="font-medium">{u.display_name}</div><div className="text-xs text-muted-foreground">{u.username}{u.email ? ` · ${u.email}` : ""}</div>{(u.sso_linked || u.sso_only) && <Badge tone="outline" className="mt-1">{u.sso_linked ? "SSO linked" : "SSO only · not activated yet"}</Badge>}</div>, sort: (u: any) => u.display_name },
        { key: "r", header: "Role", cell: (u: any) => u.id === me?.id ? <Badge tone="primary">{label.get(u.role) as string}</Badge> : <div className="w-44"><Select ariaLabel={`Role for ${u.display_name}`} value={u.role} onChange={(v) => (v === "auditor" && !u.expires_at ? setExp({ id: u.id, name: u.display_name, date: null, role: v }) : update.mutate({ id: u.id, body: { role: v } }))} options={ropts} /></div> },
        { key: "e", header: "Expires", cell: (u: any) => (u.expires_at ? (new Date(u.expires_at) <= new Date() ? <Badge tone="critical">Expired {fmtDate(u.expires_at)}</Badge> : <span className="whitespace-nowrap">{fmtDate(u.expires_at)}</span>) : <span className="text-muted-foreground">Never</span>), sort: (u: any) => u.expires_at ?? "9" },
        { key: "a", header: "Status", cell: (u: any) => (u.active ? (u.locked_until && new Date(u.locked_until) > new Date() ? <Badge tone="warning">Locked</Badge> : <Badge tone="good">Active</Badge>) : <Badge tone="outline">Disabled</Badge>) },
        { key: "l", header: "Last sign-in", cell: (u: any) => fmtDate(u.last_login_at, true) },
        { key: "x", header: "", cell: (u: any) => u.id !== me?.id && <div className="flex justify-end gap-1"><Button size="sm" variant="ghost" onClick={() => setEdit({ id: u.id, name: u.display_name, password: "" })}><KeyRound /> Reset</Button><Button size="sm" variant="ghost" onClick={() => setExp({ id: u.id, name: u.display_name, date: u.expires_at ? u.expires_at.slice(0, 10) : null, role: u.role })}>Expiry</Button><Button size="sm" variant="ghost" onClick={() => update.mutate({ id: u.id, body: { active: !u.active } })}>{u.active ? "Disable" : "Enable"}</Button></div> },
      ]} />
      <Dialog open={!!nu} onOpenChange={(o) => !o && setNu(null)} title="Add user" footer={<Button loading={create.isPending} onClick={() => { const { expires_on, ...rest } = nu; create.mutate(clean({ ...rest, password: rest.sso_only ? null : rest.password, sso_only: !!rest.sso_only, expires_at: expires_on ? `${expires_on}T00:00:00Z` : null })); }}>Create user</Button>}>
        {nu && <div className="grid gap-3 sm:grid-cols-2"><Field label="Name"><Input value={nu.display_name} onChange={(e) => setNu({ ...nu, display_name: e.target.value })} /></Field><Field label="Username"><Input value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} /></Field><Field label="Email"><Input value={nu.email} onChange={(e) => setNu({ ...nu, email: e.target.value })} /></Field><Field label="Role"><Select value={nu.role} onChange={(v) => setNu({ ...nu, role: v })} options={ropts} /></Field><Field label="Account expires" required={nu.role === "auditor"} hint={nu.role === "auditor" ? "Auditor accounts must expire. Access stops at the start of this day (UTC)." : "Optional. Access stops at the start of this day (UTC)."}><DateInput value={nu.expires_on ?? null} onChange={(v) => setNu({ ...nu, expires_on: v })} /></Field><label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={!!nu.sso_only} onChange={(e) => setNu({ ...nu, sso_only: e.target.checked })} /> Signs in with single sign-on only (no password)</label>{nu.sso_only ? <p className="text-xs text-muted-foreground sm:col-span-2">Enter the email they use with Microsoft or Google. Their first SSO sign-in activates the account.</p> : <Field label="Temporary password" className="sm:col-span-2" hint="12+ characters; they must change it at first sign-in. If they later sign in with SSO, this password stops working."><Input type="password" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} autoComplete="new-password" /></Field>}</div>}
      </Dialog>
      <Dialog open={!!exp} onOpenChange={(o) => !o && setExp(null)} title={`Account expiry for ${exp?.name}`}
        footer={<>{exp?.role !== "auditor" && <Button variant="ghost" onClick={() => update.mutate({ id: exp.id, body: { expires_at: null } })}>Never expires</Button>}<Button disabled={!exp?.date} loading={update.isPending} onClick={() => update.mutate({ id: exp.id, body: { expires_at: `${exp.date}T00:00:00Z`, ...(exp.role ? { role: exp.role } : {}) } })}>Save</Button></>}>
        {exp && <Field label="Expires on" hint={exp.role === "auditor" ? "Auditor accounts must expire. Access stops at the start of this day (UTC); signed-in sessions end then too." : "Access stops at the start of this day (UTC)."}><DateInput value={exp.date} onChange={(v) => setExp({ ...exp, date: v })} /></Field>}
      </Dialog>
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title={`Reset password for ${edit?.name}`} footer={<Button loading={reset.isPending} onClick={() => reset.mutate(edit)}>Reset password</Button>}>
        {edit && <Field label="New temporary password"><Input type="password" value={edit.password} onChange={(e) => setEdit({ ...edit, password: e.target.value })} autoComplete="new-password" /></Field>}
      </Dialog>
    </div>
  );
}

export function AuditLog() {
  const [type, setType] = useState<string | null>(null);
  const { data } = useApi<any[]>(`/audit-log?limit=1000${type ? `&entity_type=${type}` : ""}`, ["/audit-log", type]);
  const verify = useApi<any>("/audit-log/verify");
  const types = useApi<any[]>("/audit-log?limit=5000", ["/audit-log", "types"]);
  const allTypes = [...new Set((types.data ?? []).map((r) => r.entity_type))].sort();
  return (
    <div className="animate-fade-in">
      <PageHeader icon={AlertOctagon} title="Audit log" description="Append-only and hash-chained. Every change to ISMS records is written here automatically." />
      {verify.data && (verify.data.ok ? <div className="mb-4 flex items-center gap-2 rounded-lg border border-good/30 bg-good/5 px-4 py-3 text-sm"><CheckCircle2 className="size-4 text-good" /> Integrity check passed: the hash chain is intact.</div> : <div className="mb-4 flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/5 px-4 py-3 text-sm"><ShieldAlert className="size-4 text-critical" /> Integrity check FAILED at entry {verify.data.first_bad_id}. The log was altered outside Keystone: treat this as a security incident.</div>)}
      <DataTable rows={data ?? []} rowKey={(r: any) => r.id} search={(r: any) => `${r.actor_name} ${r.summary} ${r.action}`} toolbar={<div className="w-56"><Select ariaLabel="Filter by record type" value={type} onChange={setType} allowEmpty emptyLabel="All record types" placeholder="All record types" options={allTypes.map((t) => ({ value: t, label: t }))} /></div>} columns={[
        { key: "i", header: "#", cell: (r: any) => <span className="tabular-nums text-muted-foreground">{r.id}</span>, className: "w-16" },
        { key: "t", header: "When", cell: (r: any) => <span className="whitespace-nowrap">{fmtDate(r.ts, true)}</span> },
        { key: "a", header: "Actor", cell: (r: any) => r.actor_name },
        { key: "ac", header: "Action", cell: (r: any) => <Badge tone={r.action === "delete" ? "critical" : r.action.startsWith("login_failed") ? "warning" : "outline"}>{r.action}</Badge> },
        { key: "s", header: "Summary", cell: (r: any) => <div className="max-w-lg"><div>{r.summary}</div>{r.changes && <details className="mt-1 text-xs text-muted-foreground"><summary className="cursor-pointer">changes</summary><pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-muted p-2">{JSON.stringify(r.changes, null, 1)}</pre></details>}</div> },
      ]} />
    </div>
  );
}

export function Account() {
  const { me, refresh } = useAuth();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const change = useAction(() => api("/auth/change-password", { body: { current: f.current, new: f.next } }), { success: "Password changed. Your other sessions were signed out.", onSuccess: () => { setF({ current: "", next: "", confirm: "" }); void refresh(); } });
  return (
    <div className="animate-fade-in max-w-3xl">
      <PageHeader icon={KeyRound} title="My account" />
      <div className="grid gap-6 md:grid-cols-2">
        <Card><CardHeader title="Profile" /><CardBody><KeyValue items={[["Name", me?.display_name], ["Username", me?.username], ["Email", me?.email], ["Role", me?.role_label]]} /><details className="mt-4 text-xs text-muted-foreground"><summary className="cursor-pointer">What my role allows</summary><p className="mt-2">{me?.permissions.join(", ")}</p></details></CardBody></Card>
        <Card><CardHeader title="Change password" /><CardBody className="space-y-3">
          <Field label="Current password"><Input type="password" value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} autoComplete="current-password" /></Field>
          <Field label="New password" hint="12+ characters with three of: lowercase, uppercase, digit, symbol."><Input type="password" value={f.next} onChange={(e) => setF({ ...f, next: e.target.value })} autoComplete="new-password" /></Field>
          <Field label="Confirm"><Input type="password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} autoComplete="new-password" /></Field>
          <Button disabled={!f.next || f.next !== f.confirm} loading={change.isPending} onClick={() => change.mutate(undefined)}>Change password</Button>
        </CardBody></Card>
        <DigestPreference />
      </div>
    </div>
  );
}

export function Reports() {
  const { data } = useApi<string[]>("/reports");
  const fws = useApi<any[]>("/frameworks");
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Activity} title="Reports & exports" description="Spreadsheet exports are written to the audit log and protected against formula injection. Treat them as confidential." />
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {(data ?? []).map((n) => (
          <Card key={n}><CardBody className="flex items-center justify-between"><span className="font-medium">{n}</span><a href={downloadUrl(`/reports/${encodeURIComponent(n)}.xlsx`)}><Button variant="outline" size="sm"><Download /> Excel</Button></a></CardBody></Card>
        ))}
        {(fws.data ?? []).map((f) => (
          <Card key={f.code}><CardBody className="flex items-center justify-between"><span className="font-medium">SoA · {f.name}</span><div className="flex gap-1"><a href={downloadUrl(`/soa/${f.code}/export.xlsx`)}><Button variant="outline" size="sm">Excel</Button></a><a href={downloadUrl(`/soa/${f.code}/export.docx`)}><Button variant="outline" size="sm">Word</Button></a></div></CardBody></Card>
        ))}
        <Card><CardBody className="flex items-center justify-between"><span className="font-medium">Entra remediation candidates</span><a href={downloadUrl("/exposure/remediation.xlsx")}><Button variant="outline" size="sm"><Download /> Excel</Button></a></CardBody></Card>
      </div>
    </div>
  );
}

const FEATURE_LABEL: Record<string, string> = { policy_assistant: "Policy assistant", questionnaire_answers: "Questionnaire answers" };

export function AiSettings() {
  const { data } = useApi<any>("/ai/settings");
  const [form, setForm] = useState<any>(null);
  const [key, setKey] = useState("");
  const loadedKey = data ? `${data.enabled}|${data.model}|${data.effort}|${data.max_calls_per_user_hour}|${data.monthly_token_budget}` : null;
  const [formKey, setFormKey] = useState<string | null>(null);
  if (data && loadedKey !== formKey) { setFormKey(loadedKey); setForm({ enabled: data.enabled, model: data.model, effort: data.effort, max_calls_per_user_hour: data.max_calls_per_user_hour, monthly_token_budget: data.monthly_token_budget }); } // reload after save
  const save = useAction((extra: any) => api("/ai/settings", { method: "PATCH", body: { ...form, ...(key ? { api_key: key } : {}), ...extra } }), { success: "AI settings saved.", invalidate: ["/ai"], onSuccess: () => setKey("") });
  if (!data || !form) return <Skeleton className="h-96" />;
  const keyLabel = data.key_source === "settings" ? "Stored in Keystone (encrypted)" : data.key_source === "environment" ? "From the ANTHROPIC_API_KEY environment variable" : "No key";
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Sparkles} title="AI" description="Optional Claude features: the policy assistant and security-questionnaire drafting. Keystone works fully without them." />
      <div className="grid gap-5 lg:grid-cols-[1fr_22rem]">
        <Card>
          <CardHeader title="Claude API" description="Requests go to Anthropic's API only when someone uses an AI feature. Each call is recorded below and in the audit log." />
          <CardBody className="space-y-5">
            <Switch checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} label={form.enabled ? "AI features are on" : "AI features are off"} />
            <Field label="API key" hint={<>Current: {keyLabel}. The key is write-only and can never be read back. Leave empty to keep it.</>}>
              <Input type="password" autoComplete="off" placeholder={data.key_source ? "•••••••• (set)" : "sk-ant-…"} value={key} onChange={(e) => setKey(e.target.value)} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Model" hint="Claude Opus 5.5 is the default.">
                <Input list="ai-models" value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} />
                <datalist id="ai-models">{data.suggested_models.map((m: string) => <option key={m} value={m} />)}</datalist>
              </Field>
              <Field label="Effort" hint="Higher effort is more thorough, slower and costs more.">
                <Select value={form.effort} onChange={(v) => setForm({ ...form, effort: v })} options={data.efforts.map((e: string) => ({ value: e, label: titleCase(e) }))} />
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Calls per user per hour" hint="Each person can start AI actions until they reach this many calls in an hour.">
                <Input type="number" min={1} max={10000} value={form.max_calls_per_user_hour} onChange={(e) => setForm({ ...form, max_calls_per_user_hour: Number(e.target.value) })} />
              </Field>
              <Field label="Monthly token budget" hint={<>All users together. Used this month: {data.tokens_this_month.toLocaleString()} ({Math.min(100, Math.round((100 * data.tokens_this_month) / Math.max(1, data.monthly_token_budget)))}%).</>}>
                <Input type="number" min={10000} step={100000} value={form.monthly_token_budget} onChange={(e) => setForm({ ...form, monthly_token_budget: Number(e.target.value) })} />
              </Field>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button loading={save.isPending} onClick={() => save.mutate({})}>Save</Button>
              {data.key_source === "settings" && <Button variant="ghost" onClick={() => { if (confirm("Remove the stored API key?")) save.mutate({ clear_key: true }); }}><Trash2 /> Remove stored key</Button>}
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="What is sent" />
          <CardBody className="space-y-3 text-sm text-muted-foreground">
            <p><span className="font-medium text-foreground">Policy assistant:</span> the document's text, its linked controls, your instruction and the organisation profile (name, industry, description, scope).</p>
            <p><span className="font-medium text-foreground">Customer questionnaires:</span> the questions, the text of approved policies and approved knowledge-base answers. Draft policies are never sent.</p>
            <p>People, users, risks, incidents, evidence files and credentials are never sent. Answers cite their sources, and quotes that can't be found in a source are discarded. A person approves every answer before export.</p>
          </CardBody>
        </Card>
      </div>
      <Card className="mt-5">
        <CardHeader title="Usage" description={`${data.usage.calls} call(s) · ${data.usage.input_tokens.toLocaleString()} input and ${data.usage.output_tokens.toLocaleString()} output tokens in total`} />
        <DataTable rows={data.usage.rows} rowKey={(r: any) => r.id} empty="No AI calls yet." columns={[
          { key: "w", header: "When", cell: (r: any) => fmtDate(r.at, true) },
          { key: "u", header: "Who", cell: (r: any) => r.user },
          { key: "f", header: "Feature", cell: (r: any) => FEATURE_LABEL[r.feature] ?? r.feature },
          { key: "m", header: "Model", cell: (r: any) => <span className="font-mono text-xs">{r.model}</span> },
          { key: "t", header: "Tokens in / out", cell: (r: any) => <span className="tabular-nums">{(r.input_tokens + r.cache_read_tokens).toLocaleString()} / {r.output_tokens.toLocaleString()}</span> },
          { key: "r", header: "Result", cell: (r: any) => r.ok ? <Badge tone="good">OK</Badge> : <Badge tone="critical">{r.error ?? "Failed"}</Badge> },
        ]} />
      </Card>
    </div>
  );
}

export function EmailSettings() {
  const { data } = useApi<any>("/settings/email");
  const [f, setF] = useState<any>(null);
  const [pw, setPw] = useState("");
  const [to, setTo] = useState("");
  const loaded = data ? JSON.stringify(data) : null;
  const [formKey, setFormKey] = useState<string | null>(null);
  if (data && loaded !== formKey) { setFormKey(loaded); setF({ enabled: data.enabled, host: data.host ?? "", port: data.port, security: data.security, username: data.username ?? "", from_address: data.from_address ?? "", from_name: data.from_name, digest_hour_utc: data.digest_hour_utc }); }
  const save = useAction((extra: any) => api("/settings/email", { method: "PUT", body: { ...f, host: f.host || null, username: f.username || null, from_address: f.from_address || null, ...(pw ? { password: pw } : {}), ...extra } }), { success: "Email settings saved.", invalidate: ["/settings/email"], onSuccess: () => setPw("") });
  const test = useAction(() => api<{ sent_to: string }>("/settings/email/test", { body: to ? { to } : {} }), { success: (r) => `Test message sent to ${r.sent_to}.`, invalidate: ["/settings/email"] });
  if (!data || !f) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Mail} title="Email" description="The SMTP relay Keystone uses for the daily notification digest." />
      <div className="grid gap-5 lg:grid-cols-[1fr_22rem]">
        <Card>
          <CardHeader title="SMTP relay" description="Encrypted connections only (STARTTLS or TLS), with the certificate checked." />
          <CardBody className="space-y-4">
            <Switch checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label={f.enabled ? "Daily digests are on" : "Daily digests are off"} />
            <div className="grid gap-4 sm:grid-cols-[1fr_7rem_9rem]">
              <Field label="Relay host" hint="For example smtp.office365.com or smtp.gmail.com."><Input value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} autoComplete="off" /></Field>
              <Field label="Port"><Select value={String(f.port)} onChange={(v) => setF({ ...f, port: Number(v) })} options={[587, 465, 25, 2525].map((p) => ({ value: String(p), label: String(p) }))} /></Field>
              <Field label="Security"><Select value={f.security} onChange={(v) => setF({ ...f, security: v })} options={[{ value: "starttls", label: "STARTTLS" }, { value: "tls", label: "TLS (implicit)" }]} /></Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="User name" hint="Leave empty if the relay doesn't need sign-in."><Input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} autoComplete="off" /></Field>
              <Field label="Password" hint={data.password_set ? "Stored (encrypted, write-only). Leave empty to keep it. Changing the host removes it." : "Not set."}>
                <Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" placeholder={data.password_set ? "•••••••• (set)" : ""} />
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-[1fr_1fr_9rem]">
              <Field label="Sender address"><Input value={f.from_address} onChange={(e) => setF({ ...f, from_address: e.target.value })} placeholder="isms@example.com" /></Field>
              <Field label="Sender name"><Input value={f.from_name} onChange={(e) => setF({ ...f, from_name: e.target.value })} /></Field>
              <Field label="Send at (UTC)"><Select value={String(f.digest_hour_utc)} onChange={(v) => setF({ ...f, digest_hour_utc: Number(v) })} options={Array.from({ length: 24 }, (_, h) => ({ value: String(h), label: `${String(h).padStart(2, "0")}:00` }))} /></Field>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button loading={save.isPending} onClick={() => save.mutate({})}>Save</Button>
              {data.password_set && <Button variant="ghost" onClick={() => { if (confirm("Remove the stored SMTP password?")) save.mutate({ clear_password: true }); }}><Trash2 /> Remove password</Button>}
            </div>
            {data.last_error && <p role="alert" className="text-sm text-critical">Last attempt failed: {data.last_error}</p>}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Send a test" description="Save first. The test goes to your account's address unless you enter another." />
          <CardBody className="space-y-3">
            <Field label="Send to (optional)"><Input value={to} onChange={(e) => setTo(e.target.value)} placeholder="you@example.com" /></Field>
            <Button variant="outline" loading={test.isPending} disabled={!data.host} onClick={() => test.mutate(undefined)}><Mail /> Send test message</Button>
            <p className="text-xs text-muted-foreground">Keystone connects only to public addresses. An internal relay must be allowed by the server operator (KEYSTONE_SMTP_PRIVATE_HOSTS){data.private_hosts_allowed.length ? `; allowed now: ${data.private_hosts_allowed.join(", ")}` : ""}.</p>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

const SSO_NAMES: Record<string, string> = { entra: "Microsoft Entra ID", google: "Google" };

export function SsoSettings() {
  const { data } = useApi<any[]>("/settings/sso");
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={KeyRound} title="Single sign-on" description="Let people sign in with their Microsoft or Google work account." />
      {!data[0]?.public_url_set && <p role="alert" className="mb-4 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">Set KEYSTONE_PUBLIC_URL on the server first: the provider redirects back to that address, and sign-in can't be turned on without it.</p>}
      <div className="grid gap-5 lg:grid-cols-2">{data.map((p) => <SsoCard key={p.kind} p={p} />)}</div>
      <Card className="mt-5"><CardHeader title="How accounts are matched" /><CardBody className="space-y-2 text-sm text-muted-foreground">
        <p><span className="font-medium text-foreground">Accounts you create:</span> add the user (tick “single sign-on only” if they won't have a password) with the email they use at the provider. Their first SSO sign-in links and activates the account; after that Keystone recognises them by the provider's user ID, not their email.</p>
        <p><span className="font-medium text-foreground">Approved domains (optional):</span> anyone from an approved domain can sign in and gets an account with a basic role automatically. Give them more access under Users.</p>
        <p>Microsoft sign-in only accepts accounts from your tenant. Google sign-in requires a verified email, and approved domains must be Google Workspace domains.</p>
      </CardBody></Card>
    </div>
  );
}

function SsoCard({ p }: { p: any }) {
  const [f, setF] = useState(() => ({ enabled: p.enabled, client_id: p.client_id ?? "", tenant_id: p.tenant_id ?? "", domains: (p.allowed_domains ?? []).join(", "), jit_enabled: p.jit_enabled, jit_role: p.jit_role }));
  const [secret, setSecret] = useState("");
  const save = useAction(() => api(`/settings/sso/${p.kind}`, { method: "PUT", body: {
    enabled: f.enabled, client_id: f.client_id || null, ...(p.kind === "entra" ? { tenant_id: f.tenant_id || null } : {}),
    allowed_domains: f.domains.split(/[\s,]+/).filter(Boolean), jit_enabled: f.jit_enabled, jit_role: f.jit_role, ...(secret ? { client_secret: secret } : {}),
  } }), { success: `${SSO_NAMES[p.kind]} sign-in saved.`, invalidate: ["/settings/sso"], onSuccess: () => setSecret("") });
  return (
    <Card>
      <CardHeader title={SSO_NAMES[p.kind]} description={p.kind === "entra" ? "App registration in your Entra tenant (single tenant), web platform." : "OAuth client (web application) in your Google Cloud project."} />
      <CardBody className="space-y-4">
        <div><Switch checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label={f.enabled ? "Sign-in is on" : "Sign-in is off"} /></div>
        {p.redirect_uri && <Field label="Redirect URI to register"><div className="flex items-center gap-2"><code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1.5 text-xs">{p.redirect_uri}</code><CopyButton text={p.redirect_uri} /></div></Field>}
        {p.kind === "entra" && <Field label="Tenant ID" hint="Directory (tenant) ID, a GUID. Only accounts from this tenant can sign in."><Input value={f.tenant_id} onChange={(e) => setF({ ...f, tenant_id: e.target.value })} autoComplete="off" /></Field>}
        <Field label="Client ID"><Input value={f.client_id} onChange={(e) => setF({ ...f, client_id: e.target.value })} autoComplete="off" /></Field>
        <Field label="Client secret" hint={p.client_secret_set ? "Stored (encrypted, write-only). Leave empty to keep it." : "Not set."}><Input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" placeholder={p.client_secret_set ? "•••••••• (set)" : ""} /></Field>
        <Field label="Approved domains (optional)" hint="Comma-separated, for example alpineskihouse.com."><Input value={f.domains} onChange={(e) => setF({ ...f, domains: e.target.value })} /></Field>
        <div><Switch checked={f.jit_enabled} onChange={(v) => setF({ ...f, jit_enabled: v })} label="Create accounts automatically for approved domains" /></div>
        {f.jit_enabled && <Field label="Role for new accounts"><Select value={f.jit_role} onChange={(v) => setF({ ...f, jit_role: v })} options={[{ value: "employee", label: "Employee (portal only)" }, { value: "viewer", label: "Viewer (read-only)" }]} /></Field>}
        <div><Button loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button></div>
      </CardBody>
    </Card>
  );
}
