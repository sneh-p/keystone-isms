import { useEffect, useState } from "react";
import { AlertOctagon, Building2, CheckCircle2, Download, HardDriveDownload, HeartPulse, KeyRound, Plus, ShieldAlert, Sparkles, Stamp, Trash2, UserCog, Activity, Mail } from "lucide-react";
import { usageSummary } from "@/lib/ai-usage";
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
import { MultiSelect } from "@/components/ui/multiselect";
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
      {me?.permissions.includes("read") && <ApiTokens />}
    </div>
  );
}

/** Personal API tokens for scripts and reporting tools. */
function ApiTokens() {
  const { can } = useAuth();
  const [all, setAll] = useState(false);
  const key = `/tokens${all ? "?all=true" : ""}`;
  const { data } = useApi<any[]>(key);
  const { name } = usePeople();
  const [f, setF] = useState<any>(null);
  const [shown, setShown] = useState<string | null>(null);
  const create = useAction(() => api<any>("/tokens", { body: { name: f.name, scope: f.scope, days: Number(f.days) } }), { invalidate: ["/tokens"], onSuccess: (r: any) => { setF(null); setShown(r.token); } });
  const revoke = useAction((id: number) => api(`/tokens/${id}/revoke`, { method: "POST" }), { success: "Token revoked.", invalidate: ["/tokens"] });
  return (
    <Card className="mt-6">
      <CardHeader title="API tokens" description="For scripts and reporting tools: they act as you, with your permissions, and can't manage accounts, tokens or settings. Send as “Authorization: Bearer <token>”."
        action={<Button size="sm" onClick={() => setF({ name: "", scope: "read", days: 90 })}><Plus /> New token</Button>} />
      <CardBody className="space-y-3">
        {can("users.manage") && <Switch checked={all} onChange={setAll} label="Show everyone's tokens" />}
        <DataTable rows={data ?? []} rowKey={(t: any) => t.id} empty="No tokens." columns={[
          { key: "n", header: "Token", cell: (t: any) => <div><div className="font-medium">{t.name}</div><div className="text-xs text-muted-foreground">{t.scope === "write" ? "Read and write" : "Read only"}{all ? ` · ${name(t.user_id)}` : ""}</div></div> },
          { key: "e", header: "Expires", cell: (t: any) => fmtDate(t.expires_at) },
          { key: "u", header: "Last used", cell: (t: any) => (t.last_used_at ? `${fmtDate(t.last_used_at, true)}${t.last_used_ip ? ` from ${t.last_used_ip}` : ""}` : "Never") },
          { key: "x", header: "", cell: (t: any) => t.revoked_at ? <Badge tone="outline">Revoked</Badge> : <Button size="sm" variant="ghost" onClick={() => revoke.mutate(t.id)}>Revoke</Button> },
        ]} />
      </CardBody>
      <Dialog open={!!f} onOpenChange={(o) => !o && setF(null)} title="New API token" footer={<Button disabled={!f?.name?.trim()} loading={create.isPending} onClick={() => create.mutate(undefined)}>Create token</Button>}>
        {f && <div className="space-y-4">
          <Field label="Name" required hint="What uses it, for example “Power BI export”."><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Access"><Select value={f.scope} onChange={(v) => setF({ ...f, scope: v })} options={[{ value: "read", label: "Read only (recommended)" }, { value: "write", label: "Read and write" }]} /></Field>
          <Field label="Expires after (days)" hint="Up to a year."><Input type="number" min={1} max={365} value={f.days} onChange={(e) => setF({ ...f, days: e.target.value })} /></Field>
        </div>}
      </Dialog>
      <Dialog open={!!shown} onOpenChange={(o) => !o && setShown(null)} title="Copy the token now" description="It won't be shown again. Store it in a secrets manager, not in a script."
        footer={<Button onClick={() => setShown(null)}>Done</Button>}>
        {shown && <div className="flex items-center gap-2"><code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1.5 text-xs">{shown}</code><CopyButton text={shown} /></div>}
      </Dialog>
    </Card>
  );
}

export function Reports() {
  const { can } = useAuth();
  const { data } = useApi<string[]>("/reports");
  const fws = useApi<any[]>("/frameworks");
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Activity} title="Reports & exports" description="Spreadsheet exports are written to the audit log and protected against formula injection. Treat them as confidential." />
      <Card className="mb-4"><CardBody className="flex flex-wrap items-center justify-between gap-3">
        <div><div className="font-medium">Board summary</div><div className="text-sm text-muted-foreground">One page for management: readiness, how the headline figures moved over the last 12 weeks, top risks and what needs a decision.</div></div>
        <div className="flex gap-2"><a href={downloadUrl("/reports/board.pdf")}><Button><Download /> PDF</Button></a><a href={downloadUrl("/reports/board.docx")}><Button variant="outline"><Download /> Word</Button></a></div>
      </CardBody></Card>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {(data ?? []).map((n) => (
          <Card key={n}><CardBody className="flex items-center justify-between"><span className="font-medium">{n}</span><a href={downloadUrl(`/reports/${encodeURIComponent(n)}.xlsx`)}><Button variant="outline" size="sm"><Download /> Excel</Button></a></CardBody></Card>
        ))}
        {(fws.data ?? []).map((f) => (
          <Card key={f.code}><CardBody className="flex items-center justify-between"><span className="font-medium">SoA · {f.name}</span><div className="flex gap-1"><a href={downloadUrl(`/soa/${f.code}/export.xlsx`)}><Button variant="outline" size="sm">Excel</Button></a><a href={downloadUrl(`/soa/${f.code}/export.docx`)}><Button variant="outline" size="sm">Word</Button></a></div></CardBody></Card>
        ))}
        <Card><CardBody className="flex items-center justify-between"><span className="font-medium">Entra remediation candidates</span><a href={downloadUrl("/exposure/remediation.xlsx")}><Button variant="outline" size="sm"><Download /> Excel</Button></a></CardBody></Card>
      </div>
      {can("org.write") && <ReportSchedules />}
    </div>
  );
}

/** Reports emailed on a schedule to chosen Keystone users. */
function ReportSchedules() {
  const { data } = useApi<any>("/report-schedules");
  const { people, name } = usePeople();
  const [edit, setEdit] = useState<any>(null);
  const inv = ["/report-schedules"];
  const save = useAction(() => {
    const body = { name: edit.name, report: edit.report, frequency: edit.frequency, recipient_ids: edit.recipient_ids.map(Number), next_run_on: edit.next_run_on, enabled: edit.enabled };
    return edit.id ? api(`/report-schedules/${edit.id}`, { method: "PATCH", body }) : api("/report-schedules", { body });
  }, { success: "Schedule saved.", invalidate: inv, onSuccess: () => setEdit(null) });
  const sendNow = useAction((id: number) => api<any>(`/report-schedules/${id}/send`, { method: "POST" }), { success: (r: any) => (r.last_error ? `Not sent: ${r.last_error}` : "Sent."), invalidate: inv });
  const del = useAction((id: number) => api(`/report-schedules/${id}`, { method: "DELETE" }), { success: "Schedule removed.", invalidate: inv });
  if (!data) return null;
  const labels: Record<string, string> = data.reports;
  return (
    <Card className="mt-6">
      <CardHeader title="Scheduled emails" description="Send a report by email to Keystone users on a schedule. It's built with the permissions of whoever last saved the schedule, and only recipients who can still read the ISMS receive it."
        action={<Button size="sm" onClick={() => setEdit({ name: "Monthly board pack", report: "board_pdf", frequency: "monthly", recipient_ids: [], next_run_on: new Date().toISOString().slice(0, 10), enabled: true })}><Plus /> New schedule</Button>} />
      <DataTable rows={data.schedules} rowKey={(r: any) => r.id} empty="No scheduled emails." onRowClick={(r: any) => setEdit({ ...r, recipient_ids: r.recipient_ids.map(String) })} columns={[
        { key: "n", header: "Schedule", cell: (r: any) => <div><div className="font-medium">{r.name}{!r.enabled && <Badge tone="outline" className="ml-2">Paused</Badge>}</div><div className="text-xs text-muted-foreground">{labels[r.report] ?? r.report} · {titleCase(r.frequency)}</div></div> },
        { key: "r", header: "To", cell: (r: any) => <span className="text-xs">{r.recipient_ids.map((id: number) => name(id)).join(", ")}</span> },
        { key: "d", header: "Next", cell: (r: any) => fmtDate(r.next_run_on) },
        { key: "l", header: "Last sent", cell: (r: any) => r.last_error ? <span className="text-xs text-critical">{r.last_error}</span> : r.last_sent_at ? fmtDate(r.last_sent_at, true) : "—" },
        { key: "x", header: "", cell: (r: any) => <span className="flex gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="outline" loading={sendNow.isPending && sendNow.variables === r.id} onClick={() => sendNow.mutate(r.id)}>Send now</Button>
          <Button size="sm" variant="ghost" aria-label={`Remove ${r.name}`} onClick={() => { if (confirm(`Remove “${r.name}”?`)) del.mutate(r.id); }}><Trash2 /></Button></span> },
      ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title={edit?.id ? edit.name : "New scheduled email"} footer={<Button disabled={!edit?.name?.trim() || !edit?.recipient_ids?.length || !edit?.next_run_on} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
        {edit && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" required className="sm:col-span-2"><Input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
          <Field label="Report"><Select value={edit.report} onChange={(v) => setEdit({ ...edit, report: v })} options={Object.entries(labels).map(([value, label]) => ({ value, label }))} /></Field>
          <Field label="How often"><EnumSelect value={edit.frequency} onChange={(v) => setEdit({ ...edit, frequency: v })} values={["weekly", "monthly", "quarterly"]} /></Field>
          <Field label="Recipients" required className="sm:col-span-2"><MultiSelect value={edit.recipient_ids} onChange={(v) => setEdit({ ...edit, recipient_ids: v })} options={people.map((p) => ({ value: String(p.id), label: p.display_name }))} /></Field>
          <Field label={edit.id ? "Next send" : "First send"}><DateInput value={edit.next_run_on} onChange={(v) => setEdit({ ...edit, next_run_on: v })} /></Field>
          <div className="self-end"><Switch checked={edit.enabled} onChange={(v) => setEdit({ ...edit, enabled: v })} label={edit.enabled ? "Active" : "Paused"} /></div>
        </div>}
      </Dialog>
    </Card>
  );
}

const FEATURE_LABEL: Record<string, string> = { policy_assistant: "Policy assistant", questionnaire_answers: "Questionnaire answers", control_narrative: "Control narratives", risk_suggestions: "Risk suggestions" };

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
            <p><span className="font-medium text-foreground">Control narratives:</span> the control, the titles of the requirements and approved policies it maps to, its current implementation notes and the organisation profile.</p>
            <p><span className="font-medium text-foreground">Risk suggestions:</span> the organisation profile, asset names and ratings, supplier names and services, and the control catalogue. Existing risks are never sent; duplicates are filtered out in Keystone.</p>
            <p>People, users, risks, incidents, evidence files and credentials are never sent. Answers cite their sources, and quotes that can't be found in a source are discarded. A person approves every answer before export.</p>
          </CardBody>
        </Card>
      </div>
      <Card className="mt-5">
        <CardHeader title="Usage" description={usageSummary(data.usage)} />
        <DataTable rows={data.usage.rows} rowKey={(r: any) => r.id} empty="No AI calls yet." columns={[
          { key: "w", header: "When", cell: (r: any) => fmtDate(r.at, true) },
          { key: "u", header: "Who", cell: (r: any) => r.user },
          { key: "f", header: "Feature", cell: (r: any) => FEATURE_LABEL[r.feature] ?? r.feature },
          { key: "m", header: "Model", cell: (r: any) => <span className="font-mono text-xs">{r.model}</span> },
          { key: "t", header: "Tokens in / out", cell: (r: any) => <span className="tabular-nums">{(r.input_tokens + r.cache_write_tokens + r.cache_read_tokens).toLocaleString()} / {r.output_tokens.toLocaleString()}</span> },
          { key: "c", header: "From cache", cell: (r: any) => <span className="tabular-nums">{r.cache_read_tokens.toLocaleString()}</span> },
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

const SSO_NAMES: Record<string, string> = { entra: "Microsoft Entra ID", google: "Google", okta: "Okta" };
const SSO_HELP: Record<string, string> = { entra: "App registration in your Entra tenant (single tenant), web platform.", google: "OAuth client (web application) in your Google Cloud project.",
  okta: "OIDC web app integration in your Okta org (Applications > Create App Integration > OIDC, Web Application), with the email scope." };

export function SsoSettings() {
  const { data } = useApi<any[]>("/settings/sso");
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={KeyRound} title="Single sign-on" description="Let people sign in with their Microsoft or Google work account." />
      {!data[0]?.public_url_set && <p role="alert" className="mb-4 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">Set KEYSTONE_PUBLIC_URL on the server first: the provider redirects back to that address, and sign-in can't be turned on without it.</p>}
      <SsoRequired />
      <div className="grid gap-5 lg:grid-cols-2">{data.map((p) => <SsoCard key={p.kind} p={p} />)}</div>
      <Card className="mt-5"><CardHeader title="How accounts are matched" /><CardBody className="space-y-2 text-sm text-muted-foreground">
        <p><span className="font-medium text-foreground">Accounts you create:</span> add the user (tick “single sign-on only” if they won't have a password) with the email they use at the provider. Their first SSO sign-in links and activates the account; after that Keystone recognises them by the provider's user ID, not their email.</p>
        <p><span className="font-medium text-foreground">Approved domains (optional):</span> anyone from an approved domain can sign in and gets an account with a basic role automatically. Give them more access under Users.</p>
        <p>Microsoft sign-in only accepts accounts from your tenant. Google sign-in requires a verified email, and approved domains must be Google Workspace domains.</p>
      </CardBody></Card>
    </div>
  );
}

function SsoRequired() {
  const { data } = useApi<{ required: boolean; providers_on: string[] }>("/settings/sso-policy");
  const save = useAction((required: boolean) => api("/settings/sso-policy", { method: "PUT", body: { required } }), { success: (r: any) => (r.required ? "Single sign-on is now required." : "Password sign-in is allowed again."), invalidate: ["/settings/sso"] });
  if (!data) return null;
  return (
    <Card className="mb-5"><CardBody className="space-y-2">
      <div><Switch checked={data.required} onChange={(v) => save.mutate(v)} label="Require single sign-on" disabled={!data.required && data.providers_on.length === 0} /></div>
      <p className="text-sm text-muted-foreground">Everyone except administrators must sign in with Microsoft or Google. Administrators keep their password as the emergency route if the provider is unavailable, so keep their passwords strong and their number small.{data.providers_on.length === 0 && " Turn on a sign-in provider first."}</p>
    </CardBody></Card>
  );
}

function SsoCard({ p }: { p: any }) {
  const [f, setF] = useState(() => ({ enabled: p.enabled, client_id: p.client_id ?? "", tenant_id: p.tenant_id ?? "", org_domain: p.org_domain ?? "", domains: (p.allowed_domains ?? []).join(", "), jit_enabled: p.jit_enabled, jit_role: p.jit_role }));
  const [secret, setSecret] = useState("");
  const save = useAction(() => api(`/settings/sso/${p.kind}`, { method: "PUT", body: {
    enabled: f.enabled, client_id: f.client_id || null, ...(p.kind === "entra" ? { tenant_id: f.tenant_id || null } : {}), ...(p.kind === "okta" ? { org_domain: f.org_domain || null } : {}),
    allowed_domains: f.domains.split(/[\s,]+/).filter(Boolean), jit_enabled: f.jit_enabled, jit_role: f.jit_role, ...(secret ? { client_secret: secret } : {}),
  } }), { success: `${SSO_NAMES[p.kind]} sign-in saved.`, invalidate: ["/settings/sso"], onSuccess: () => setSecret("") });
  return (
    <Card>
      <CardHeader title={SSO_NAMES[p.kind] ?? p.kind} description={SSO_HELP[p.kind]} />
      <CardBody className="space-y-4">
        <div><Switch checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label={f.enabled ? "Sign-in is on" : "Sign-in is off"} /></div>
        {p.redirect_uri && <Field label="Redirect URI to register"><div className="flex items-center gap-2"><code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1.5 text-xs">{p.redirect_uri}</code><CopyButton text={p.redirect_uri} /></div></Field>}
        {p.kind === "okta" && <Field label="Okta domain" hint="For example yourcompany.okta.com. Changing it removes the stored client secret."><Input value={f.org_domain} onChange={(e) => setF({ ...f, org_domain: e.target.value })} autoComplete="off" placeholder="yourcompany.okta.com" /></Field>}
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

function fmtBytes(n?: number | null): string {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

const BACKUP_TONE: Record<string, "good" | "warning" | "critical" | "neutral"> = { ok: "good", warning: "warning", failed: "critical", running: "neutral" };

/** Administrators: scheduled jobs, backups, database and virus scanner, and a button to back up now. */
export function SystemHealth() {
  const { data } = useApi<any>("/system/health");
  const run = useAction(() => api("/system/backups", { body: {} }), { success: "Backup started. It appears below when it finishes.", invalidate: ["/system/health"] });
  if (!data) return <Skeleton className="h-96" />;
  const ok = (good: boolean, yes: string, no: string) => <Badge tone={good ? "good" : "critical"}>{good ? <CheckCircle2 className="h-3 w-3" /> : <AlertOctagon className="h-3 w-3" />}{good ? yes : no}</Badge>;
  return (
    <div className="animate-fade-in space-y-5">
      <PageHeader icon={HeartPulse} title="System health" description="Scheduled jobs, backups and the services Keystone depends on. Administrators are notified when something here stops working." />
      {data.problems.length > 0 ? (
        <div role="alert" className="rounded-lg border border-critical/30 bg-critical/5 p-4 text-sm">
          <p className="font-medium">Needs attention</p>
          <ul className="mt-1 list-disc pl-5">{data.problems.map((p: any) => <li key={p.key}>{p.title}</li>)}</ul>
        </div>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground"><CheckCircle2 className="h-4 w-4 text-good" /> Everything is working.</p>
      )}
      <div className="grid gap-5 lg:grid-cols-[22rem_1fr]">
        <Card>
          <CardHeader title="Services" />
          <CardBody>
            <KeyValue items={[
              ["Database", <span key="db">{data.database === "postgresql" ? "PostgreSQL" : "SQLite"} <span className="text-muted-foreground">(schema {data.schema_revision ?? "unknown"})</span></span>],
              ["Scheduler", ok(data.scheduler_running, "Running", "Not running")],
              ["Virus scanner", ok(data.virus_scanner === "ok", "Reachable", "Unavailable: vendor uploads are refused")],
              ["Email", <Badge key="m" tone={data.email === "configured" ? "good" : "outline"}>{data.email === "configured" ? "Configured" : "Not configured"}</Badge>],
            ]} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Backups" description="Each backup is test-restored into a scratch database before it counts as verified. Restoring is done on the server (python -m keystone.ops restore); see the admin guide."
            action={<Button size="sm" loading={run.isPending} onClick={() => run.mutate(undefined)}><HardDriveDownload /> Back up now</Button>} />
          <DataTable rows={data.backups} rowKey={(r: any) => r.id} empty="No backups yet. The first runs a day after Keystone starts, or use Back up now." columns={[
            { key: "w", header: "Started", cell: (r: any) => fmtDate(r.started_at, true) },
            { key: "s", header: "Result", cell: (r: any) => <span className="flex flex-wrap items-center gap-1"><Badge tone={BACKUP_TONE[r.status] ?? "neutral"}>{r.status === "ok" ? "OK" : titleCase(r.status)}</Badge>{r.verified && <Badge tone="good"><CheckCircle2 className="h-3 w-3" />Verified</Badge>}</span> },
            { key: "z", header: "Size", cell: (r: any) => <span className="tabular-nums">{fmtBytes(r.size_bytes)}</span> },
            { key: "c", header: "Contents", cell: (r: any) => r.rows == null ? "—" : <span className="tabular-nums">{r.rows.toLocaleString()} rows, {r.files} files</span> },
            { key: "d", header: "Notes", cell: (r: any) => <span className="text-muted-foreground">{r.detail ?? r.filename ?? ""}</span> },
          ]} />
        </Card>
      </div>
      <Card>
        <CardHeader title="Scheduled jobs" description="An administrator alert is raised after two failures in a row." />
        <DataTable rows={data.jobs} rowKey={(r: any) => r.name} columns={[
          { key: "n", header: "Job", cell: (r: any) => <span className="font-medium">{r.name}</span> },
          { key: "e", header: "Runs every", cell: (r: any) => r.every_minutes >= 1440 ? `${r.every_minutes / 1440} day(s)` : r.every_minutes >= 60 ? `${r.every_minutes / 60} hour(s)` : `${r.every_minutes} minutes` },
          { key: "l", header: "Last run", cell: (r: any) => r.last_finished ? fmtDate(r.last_finished, true) : "Not yet" },
          { key: "o", header: "Result", cell: (r: any) => r.last_ok == null ? <Badge tone="outline">Not run</Badge> : r.last_ok ? <Badge tone="good">OK</Badge> : <Badge tone="critical">Failed{r.consecutive_failures > 1 ? ` ×${r.consecutive_failures}` : ""}{r.last_error ? `: ${r.last_error}` : ""}</Badge> },
        ]} />
      </Card>
    </div>
  );
}

/** SCIM provisioning: tokens an identity provider uses to create, update and deactivate accounts. */
export function Provisioning() {
  const { data } = useApi<any>("/settings/scim");
  const [f, setF] = useState<any>(null);
  const [shown, setShown] = useState<string | null>(null);
  const create = useAction(() => api<any>("/settings/scim", { body: { label: f.label, default_role: f.default_role, days: f.days ? Number(f.days) : null } }), { invalidate: ["/settings/scim"], onSuccess: (r: any) => { setF(null); setShown(r.token); } });
  const revoke = useAction((id: number) => api(`/settings/scim/${id}/revoke`, { method: "POST" }), { success: "Token revoked.", invalidate: ["/settings/scim"] });
  if (!data) return <Skeleton className="h-96" />;
  return (
    <div className="animate-fade-in space-y-5">
      <PageHeader icon={UserCog} title="Provisioning (SCIM)" description="Let Microsoft Entra ID, Okta or another identity provider create, update and deactivate Keystone accounts."
        actions={<Button onClick={() => setF({ label: "", default_role: "employee", days: 365 })}><Plus /> New token</Button>} />
      <Card>
        <CardHeader title="Connection details" description="Enter these in the identity provider's provisioning settings (Entra: Enterprise app > Provisioning; Okta: app > Provisioning > Integration)." />
        <CardBody>
          {data.base_url ? <KeyValue items={[["Tenant URL", <span key="u" className="flex items-center gap-2"><code className="break-all">{data.base_url}</code><CopyButton text={data.base_url} /></span>], ["Secret token", "Create one below; it's shown once"]]} />
            : <p className="text-sm text-critical">Set KEYSTONE_PUBLIC_URL on the server first: the identity provider needs Keystone's public address.</p>}
          <ul className="mt-4 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            <li>New accounts get the token's basic role and sign in with single sign-on only. Give other roles in Users.</li>
            <li>The identity provider can deactivate accounts it manages; it can never see, change or deactivate administrators.</li>
            <li>Removing a user in the identity provider deactivates the account; its history stays in the audit log.</li>
          </ul>
        </CardBody>
      </Card>
      <DataTable rows={data.tokens} rowKey={(t: any) => t.id} empty="No tokens yet." columns={[
        { key: "l", header: "Token", cell: (t: any) => <div><div className="font-medium">{t.label}</div><div className="text-xs text-muted-foreground">New accounts: {titleCase(t.default_role)}</div></div> },
        { key: "c", header: "Created", cell: (t: any) => fmtDate(t.created_at) },
        { key: "e", header: "Expires", cell: (t: any) => (t.expires_at ? fmtDate(t.expires_at) : "Never") },
        { key: "u", header: "Last used", cell: (t: any) => (t.last_used_at ? fmtDate(t.last_used_at, true) : "Never") },
        { key: "s", header: "", cell: (t: any) => t.revoked_at ? <Badge tone="outline">Revoked {fmtDate(t.revoked_at)}</Badge> : <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Revoke “${t.label}”? Provisioning stops until a new token is entered.`)) revoke.mutate(t.id); }}>Revoke</Button> },
      ]} />
      <Dialog open={!!f} onOpenChange={(o) => !o && setF(null)} title="New provisioning token" footer={<Button disabled={!f?.label?.trim()} loading={create.isPending} onClick={() => create.mutate(undefined)}>Create token</Button>}>
        {f && <div className="space-y-4">
          <Field label="Label" required hint="Which identity provider uses it."><Input value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} placeholder="Microsoft Entra ID" /></Field>
          <Field label="Role for new accounts"><Select value={f.default_role} onChange={(v) => setF({ ...f, default_role: v })} options={[{ value: "employee", label: "Employee (portal only)" }, { value: "viewer", label: "Viewer (read-only)" }]} /></Field>
          <Field label="Expires after (days)" hint="Up to three years. Set a reminder to rotate it."><Input type="number" min={1} max={1095} value={f.days} onChange={(e) => setF({ ...f, days: e.target.value })} /></Field>
        </div>}
      </Dialog>
      <Dialog open={!!shown} onOpenChange={(o) => !o && setShown(null)} title="Copy the token now" description="It won't be shown again. Paste it into the identity provider's Secret Token field."
        footer={<Button onClick={() => setShown(null)}>Done</Button>}>
        {shown && <div className="flex items-center gap-2"><code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1.5 text-xs">{shown}</code><CopyButton text={shown} /></div>}
      </Dialog>
    </div>
  );
}

const CHANNEL_LABEL: Record<string, string> = { slack: "Slack", teams: "Microsoft Teams", webhook: "Webhook" };
const CHANNEL_HELP: Record<string, string> = {
  slack: "An incoming webhook URL from your Slack app (https://hooks.slack.com/services/...).",
  teams: "In Teams: a channel's Workflows > “Post to a channel when a webhook request is received”, then copy its URL.",
  webhook: "Any public HTTPS endpoint. Requests are signed: check X-Keystone-Signature with the secret shown once after saving.",
};

/** Slack, Teams and signed webhooks: which events go where. */
export function Channels() {
  const { data } = useApi<any>("/outbound/destinations");
  const [edit, setEdit] = useState<any>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const inv = ["/outbound/destinations"];
  const save = useAction(() => {
    const body: any = { name: edit.name, events: edit.events, enabled: edit.enabled, ...(edit.url ? { url: edit.url } : {}) };
    return edit.id ? api(`/outbound/destinations/${edit.id}`, { method: "PATCH", body }) : api<any>("/outbound/destinations", { body: { ...body, kind: edit.kind } });
  }, { success: "Saved.", invalidate: inv, onSuccess: (r: any) => { setEdit(null); if (r.signing_secret) setSecret(r.signing_secret); } });
  const test = useAction((id: number) => api<any>(`/outbound/destinations/${id}/test`, { method: "POST" }), { success: (r: any) => (r.status === "sent" ? "Test message sent." : `Test failed: ${r.last_error}`), invalidate: inv });
  const del = useAction((id: number) => api(`/outbound/destinations/${id}`, { method: "DELETE" }), { success: "Removed.", invalidate: inv });
  if (!data) return <Skeleton className="h-96" />;
  const events: Record<string, string> = data.events;
  return (
    <div className="animate-fade-in space-y-5">
      <PageHeader icon={Mail} title="Chat and webhooks" description="Send important events to a Slack or Teams channel, or to your own systems as signed webhooks. Messages carry a title and a link back to Keystone, nothing more."
        actions={<Button onClick={() => setEdit({ kind: "slack", name: "", url: "", events: ["incident.created", "finding.opened", "vulnerability.known_exploited", "system.alert"], enabled: true })}><Plus /> Add destination</Button>} />
      <DataTable rows={data.destinations} rowKey={(d: any) => d.id} empty="No destinations yet." onRowClick={(d: any) => setEdit({ ...d, url: "" })} columns={[
        { key: "n", header: "Destination", cell: (d: any) => <div><div className="font-medium">{d.name}{!d.enabled && <Badge tone="outline" className="ml-2">Paused</Badge>}</div><div className="text-xs text-muted-foreground">{CHANNEL_LABEL[d.kind]} · {d.url_host}</div></div> },
        { key: "e", header: "Events", cell: (d: any) => <span className="text-xs">{d.events.map((e: string) => events[e] ?? e).join(", ")}</span> },
        { key: "s", header: "Last delivery", cell: (d: any) => d.last_status === "error" ? <span className="text-xs text-critical">{d.last_error}</span> : d.last_sent_at ? fmtDate(d.last_sent_at, true) : "—" },
        { key: "x", header: "", cell: (d: any) => <span className="flex gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="outline" loading={test.isPending && test.variables === d.id} onClick={() => test.mutate(d.id)}>Send test</Button>
          <Button size="sm" variant="ghost" aria-label={`Remove ${d.name}`} onClick={() => { if (confirm(`Remove ${d.name}?`)) del.mutate(d.id); }}><Trash2 /></Button></span> },
      ]} />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title={edit?.id ? edit.name : "Add destination"} footer={<Button disabled={!edit?.name?.trim() || (!edit?.id && !edit?.url) || !edit?.events?.length} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
        {edit && <div className="space-y-4">
          {!edit.id && <Field label="Type"><Select value={edit.kind} onChange={(v) => setEdit({ ...edit, kind: v })} options={Object.entries(CHANNEL_LABEL).map(([value, label]) => ({ value, label }))} /></Field>}
          <Field label="Name" required><Input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} placeholder="#security-alerts" /></Field>
          <Field label="URL" hint={`${CHANNEL_HELP[edit.kind]}${edit.id ? " Stored encrypted; leave empty to keep it." : ""}`}><Input type="password" autoComplete="off" value={edit.url} onChange={(e) => setEdit({ ...edit, url: e.target.value })} placeholder={edit.id ? "•••••••• (stored)" : "https://"} /></Field>
          <fieldset><legend className="mb-2 text-sm font-medium">Events</legend>
            <div className="space-y-1">{Object.entries(events).map(([k, label]) => (
              <label key={k} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={edit.events.includes(k)} onChange={(e) => setEdit({ ...edit, events: e.target.checked ? [...edit.events, k] : edit.events.filter((x: string) => x !== k) })} />{label}</label>
            ))}</div>
          </fieldset>
          <Switch checked={edit.enabled} onChange={(v) => setEdit({ ...edit, enabled: v })} label={edit.enabled ? "Sending" : "Paused"} />
        </div>}
      </Dialog>
      <Dialog open={!!secret} onOpenChange={(o) => !o && setSecret(null)} title="Signing secret" description="Copy it now; it won't be shown again. Verify each request: HMAC-SHA256 of “<t>.<body>” with this secret must equal v1 in X-Keystone-Signature."
        footer={<Button onClick={() => setSecret(null)}>Done</Button>}>
        {secret && <div className="flex items-center gap-2"><code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1.5 text-xs">{secret}</code><CopyButton text={secret} /></div>}
      </Dialog>
    </div>
  );
}
