import { useEffect, useState } from "react";
import { AlertOctagon, Building2, CheckCircle2, Download, KeyRound, Plus, ShieldAlert, Stamp, Trash2, UserCog, Activity } from "lucide-react";
import { api, downloadUrl } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { KeyValue, PageHeader, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { clean, DateInput, EnumSelect, OwnerSelect } from "@/components/forms";

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
  const update = useAction((b: any) => api(`/users/${b.id}`, { method: "PATCH", body: { role: b.role, active: b.active } }), { success: "User updated.", invalidate: ["/users", "/people-directory"] });
  const reset = useAction((b: any) => api(`/users/${b.id}/reset-password`, { body: { password: b.password } }), { success: "Password reset; their sessions were signed out.", invalidate: ["/users"], onSuccess: () => setEdit(null) });
  if (!data || !roles.data) return <Skeleton className="h-96" />;
  const ropts = roles.data.map((r) => ({ value: r.value, label: r.label }));
  const label = new Map(roles.data.map((r) => [r.value, r.label]));
  return (
    <div className="animate-fade-in">
      <PageHeader icon={UserCog} title="Users" description="Accounts and roles. Accounts are never deleted, so the audit trail stays intact." actions={<Button onClick={() => setNu({ username: "", display_name: "", email: "", role: "viewer", password: "" })}><Plus /> Add user</Button>} />
      <DataTable rows={data} rowKey={(u: any) => u.id} search={(u: any) => `${u.username} ${u.display_name}`} columns={[
        { key: "n", header: "User", cell: (u: any) => <div><div className="font-medium">{u.display_name}</div><div className="text-xs text-muted-foreground">{u.username}{u.email ? ` · ${u.email}` : ""}</div></div>, sort: (u: any) => u.display_name },
        { key: "r", header: "Role", cell: (u: any) => u.id === me?.id ? <Badge tone="primary">{label.get(u.role) as string}</Badge> : <div className="w-44"><Select value={u.role} onChange={(v) => update.mutate({ ...u, role: v })} options={ropts} /></div> },
        { key: "a", header: "Status", cell: (u: any) => (u.active ? (u.locked_until && new Date(u.locked_until) > new Date() ? <Badge tone="warning">Locked</Badge> : <Badge tone="good">Active</Badge>) : <Badge tone="outline">Disabled</Badge>) },
        { key: "l", header: "Last sign-in", cell: (u: any) => fmtDate(u.last_login_at, true) },
        { key: "x", header: "", cell: (u: any) => u.id !== me?.id && <div className="flex justify-end gap-1"><Button size="sm" variant="ghost" onClick={() => setEdit({ id: u.id, name: u.display_name, password: "" })}><KeyRound /> Reset</Button><Button size="sm" variant="ghost" onClick={() => update.mutate({ ...u, active: !u.active })}>{u.active ? "Disable" : "Enable"}</Button></div> },
      ]} />
      <Dialog open={!!nu} onOpenChange={(o) => !o && setNu(null)} title="Add user" footer={<Button loading={create.isPending} onClick={() => create.mutate(clean(nu))}>Create user</Button>}>
        {nu && <div className="grid gap-3 sm:grid-cols-2"><Field label="Name"><Input value={nu.display_name} onChange={(e) => setNu({ ...nu, display_name: e.target.value })} /></Field><Field label="Username"><Input value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} /></Field><Field label="Email"><Input value={nu.email} onChange={(e) => setNu({ ...nu, email: e.target.value })} /></Field><Field label="Role"><Select value={nu.role} onChange={(v) => setNu({ ...nu, role: v })} options={ropts} /></Field><Field label="Temporary password" className="sm:col-span-2" hint="12+ characters; they must change it at first sign-in."><Input type="password" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} autoComplete="new-password" /></Field></div>}
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
      <DataTable rows={data ?? []} rowKey={(r: any) => r.id} search={(r: any) => `${r.actor_name} ${r.summary} ${r.action}`} toolbar={<div className="w-56"><Select value={type} onChange={setType} allowEmpty emptyLabel="All record types" placeholder="All record types" options={allTypes.map((t) => ({ value: t, label: t }))} /></div>} columns={[
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
  const { me } = useAuth();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const change = useAction(() => api("/auth/change-password", { body: { current: f.current, new: f.next } }), { success: "Password changed. Other sessions were signed out.", onSuccess: () => setF({ current: "", next: "", confirm: "" }) });
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
