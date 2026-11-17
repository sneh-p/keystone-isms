import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Check, Link2, LogOut, Mail, Plus, Users as UsersIcon } from "lucide-react";
import { CopyButton } from "@/components/CopyButton";
import { absoluteLink, api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { KeyValue, PageHeader, Progress, Section, Skeleton, Stat } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { clean, DateInput, EnumSelect } from "@/components/forms";
import { ImportButton } from "@/components/ImportDialog";

const STATUS_TONE: Record<string, any> = { onboarding: "primary", active: "good", offboarding: "warning", offboarded: "outline" };

function Compliance({ c }: { c: any }) {
  if (!c) return <span className="text-xs text-muted-foreground">Not invited</span>;
  const total = c.policies_total + c.training_total + 1;
  const done = c.policies_done + c.training_done + (c.device_ok ? 1 : 0);
  return (
    <div className="w-40">
      <Progress label="Onboarding progress" value={(100 * done) / total} tone={c.complete ? "good" : "primary"} />
      <div className="mt-1 flex gap-2 text-[11px] text-muted-foreground"><span>Policies {c.policies_done}/{c.policies_total}</span><span>Training {c.training_done}/{c.training_total}</span><span>Device {c.device_ok === null ? "—" : c.device_ok ? "✓" : "✗"}</span></div>
    </div>
  );
}

export default function People() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any>("/people");
  const [np, setNp] = useState<any>(null);
  const create = useAction((b: any) => api("/people", { body: b }), { success: "Person added.", invalidate: ["/people"], onSuccess: (r: any) => { setNp(null); setParams({ open: String(r.id) }); } });
  if (!data) return <Skeleton className="h-96" />;
  const ppl = data.people;
  const withC = ppl.filter((p: any) => p.compliance);
  return (
    <div className="animate-fade-in">
      <PageHeader icon={UsersIcon} title="People" description="Everyone in scope: invite them to the employee portal to accept policies, complete training and confirm their device is secure."
        actions={can("people.write") && <><ImportButton register="people" noun="people" invalidate={["/people", "/dashboard"]} /><Button onClick={() => setNp({ full_name: "", email: "", job_title: "", department: "", employment_type: "employee", start_date: null })}><Plus /> Add person</Button></>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        <Stat label="People" value={ppl.length} />
        <Stat label="Fully compliant" value={withC.filter((p: any) => p.compliance.complete).length} tone="good" hint={`of ${withC.length} with portal access`} />
        <Stat label="Not invited yet" value={ppl.filter((p: any) => !p.user_id).length} />
        <Stat label="Offboarding" value={ppl.filter((p: any) => p.status === "offboarding").length} tone={ppl.some((p: any) => p.status === "offboarding") ? "warning" : undefined} />
      </div>
      <DataTable rows={ppl} rowKey={(p: any) => p.id} onRowClick={(p: any) => setParams({ open: String(p.id) })} search={(p: any) => `${p.full_name} ${p.email} ${p.department ?? ""}`} columns={[
        { key: "n", header: "Person", cell: (p: any) => <div className="flex items-center gap-3"><span className="grid size-8 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-foreground">{p.full_name.split(" ").map((x: string) => x[0]).slice(0, 2).join("")}</span><div><div className="font-medium">{p.full_name}</div><div className="text-xs text-muted-foreground">{p.email}</div></div></div>, sort: (p: any) => p.full_name },
        { key: "r", header: "Role", cell: (p: any) => <div><div>{p.job_title ?? "—"}</div><div className="text-xs text-muted-foreground">{p.department}{p.employment_type === "contractor" ? " · contractor" : ""}</div></div> },
        { key: "s", header: "Status", cell: (p: any) => <Badge tone={STATUS_TONE[p.status]}>{titleCase(p.status)}</Badge>, sort: (p: any) => p.status },
        { key: "c", header: "Compliance", cell: (p: any) => <Compliance c={p.compliance} /> },
        { key: "d", header: "Start", cell: (p: any) => fmtDate(p.start_date), sort: (p: any) => p.start_date ?? "" },
      ]} />
      <Dialog open={!!np} onOpenChange={(o) => !o && setNp(null)} title="Add person" wide footer={<Button loading={create.isPending} onClick={() => create.mutate(clean(np))}>Add</Button>}>
        {np && <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Full name" required><Input value={np.full_name} onChange={(e) => setNp({ ...np, full_name: e.target.value })} /></Field>
          <Field label="Work email" required><Input type="email" value={np.email} onChange={(e) => setNp({ ...np, email: e.target.value })} /></Field>
          <Field label="Job title"><Input value={np.job_title} onChange={(e) => setNp({ ...np, job_title: e.target.value })} /></Field>
          <Field label="Department"><Input value={np.department} onChange={(e) => setNp({ ...np, department: e.target.value })} /></Field>
          <Field label="Type"><EnumSelect value={np.employment_type} onChange={(v) => setNp({ ...np, employment_type: v })} values={["employee", "contractor"]} /></Field>
          <Field label="Start date"><DateInput value={np.start_date} onChange={(v) => setNp({ ...np, start_date: v })} /></Field>
        </div>}
      </Dialog>
      {params.get("open") && <PersonDrawer person={ppl.find((p: any) => String(p.id) === params.get("open"))} items={data.offboarding_items} onClose={() => setParams({})} />}
    </div>
  );
}

function PersonDrawer({ person: p, items, onClose }: { person: any; items: Record<string, string>; onClose: () => void }) {
  const { can } = useAuth();
  const users = useApi<any[]>(can("users.manage") ? "/users" : null);
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [linkTo, setLinkTo] = useState<string | null>(null);
  const inv = ["/people"];
  const emailReady = useApi<{ ready: boolean }>("/email-status").data?.ready;
  const invite = useAction((send_email: boolean) => api(`/people/${p.id}/invite`, { method: "POST", body: { send_email } }), {
    success: (r: any) => (r.emailed_to ? `Invitation emailed to ${r.emailed_to}.` : "Invitation link created."), onSuccess: (r: any) => setInviteUrl(absoluteLink(r)) });
  const status = useAction((s: string) => api(`/people/${p.id}/status`, { body: { status: s } }), { success: "Status updated.", invalidate: inv });
  const tick = useAction((v: { item: string; done: boolean }) => api(`/people/${p.id}/offboarding`, { body: v }), { invalidate: inv });
  const complete = useAction(() => api(`/people/${p.id}/offboarding/complete`, { method: "POST" }), { success: "Offboarding complete; their sign-in was disabled.", invalidate: inv });
  const link = useAction(() => api(`/people/${p.id}/link`, { body: { user_id: linkTo ? Number(linkTo) : null } }), { success: "Account linked.", invalidate: inv });
  if (!p) return null;
  const ed = can("people.write");
  const c = p.compliance;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={p.full_name} subtitle={<span className="flex items-center gap-2"><Badge tone={STATUS_TONE[p.status]}>{titleCase(p.status)}</Badge>{p.email}</span>}>
      <div className="space-y-6">
        <KeyValue items={[["Job title", p.job_title], ["Department", p.department], ["Type", titleCase(p.employment_type)], ["Start", fmtDate(p.start_date)], ["End", fmtDate(p.end_date)]]} />
        <Section title="Portal access">
          {p.user_id ? (
            c && <ul className="space-y-2 text-sm">
              <li className="flex items-center gap-2">{c.policies_done === c.policies_total ? <Check className="size-4 text-good" /> : <span className="size-4 rounded-full border" />}Policies accepted {c.policies_done}/{c.policies_total}</li>
              <li className="flex items-center gap-2">{c.training_done === c.training_total ? <Check className="size-4 text-good" /> : <span className="size-4 rounded-full border" />}Training completed {c.training_done}/{c.training_total}</li>
              <li className="flex items-center gap-2">{c.device_ok ? <Check className="size-4 text-good" /> : <span className="size-4 rounded-full border" />}Device checklist {c.device_ok === null ? "not submitted" : c.device_ok ? "compliant" : "needs attention"} ({c.devices} device(s))</li>
            </ul>
          ) : ed && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">Send an invitation link so {p.full_name.split(" ")[0]} can sign in to the employee portal. Links work once and expire after 7 days.</p>
              {inviteUrl ? (
                <div className="flex gap-2"><Input readOnly value={inviteUrl} onFocus={(e) => e.target.select()} /><CopyButton text={inviteUrl} size="md" /></div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {emailReady && <Button onClick={() => invite.mutate(true)} loading={invite.isPending}><Mail /> Email invitation to {p.email}</Button>}
                  <Button variant={emailReady ? "outline" : "default"} onClick={() => invite.mutate(false)} loading={invite.isPending}>Create invitation link</Button>
                </div>
              )}
              {users.data && (
                <div className="flex items-end gap-2 border-t pt-3">
                  <Field label="Or link an existing Keystone account" className="flex-1"><Select value={linkTo} onChange={setLinkTo} options={users.data.map((u) => ({ value: String(u.id), label: `${u.display_name} (${u.username})` }))} /></Field>
                  <Button variant="outline" disabled={!linkTo} onClick={() => link.mutate(undefined)}><Link2 /> Link</Button>
                </div>
              )}
            </div>
          )}
        </Section>
        {ed && p.status !== "offboarded" && (
          <Section title="Lifecycle">
            {p.status !== "offboarding" ? (
              <div className="flex gap-2">
                {p.status === "onboarding" && <Button variant="outline" onClick={() => status.mutate("active")}><Check /> Mark active</Button>}
                <Button variant="outline" onClick={() => status.mutate("offboarding")}><LogOut /> Start offboarding</Button>
              </div>
            ) : (
              <div className="space-y-2">
                {Object.entries(items).map(([k, label]) => {
                  const done = p.offboarding?.[k];
                  return (
                    <label key={k} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                      <span className="flex items-center gap-2"><input type="checkbox" checked={!!done} onChange={(e) => tick.mutate({ item: k, done: e.target.checked })} />{label}</span>
                      {done && <span className="text-xs text-muted-foreground">{done.by} · {fmtDate(done.at, true)}</span>}
                    </label>
                  );
                })}
                <OwnedAssets personId={p.id} />
                <Button className="mt-2" disabled={Object.keys(items).some((k) => !p.offboarding?.[k])} loading={complete.isPending} onClick={() => complete.mutate(undefined)}>Complete offboarding</Button>
              </div>
            )}
          </Section>
        )}
      </div>
    </Sheet>
  );
}

/** Assets the leaver owns: return them, or hand them to a new owner, before offboarding completes (A.5.11). */
function OwnedAssets({ personId }: { personId: number }) {
  const { data } = useApi<any[]>(`/people/${personId}/assets`);
  if (!data?.length) return null;
  return (
    <div className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
      <div className="font-medium">They own {data.length} asset(s). Return them or give them a new owner:</div>
      <ul className="mt-1 list-disc pl-5">{data.map((a) => <li key={a.id}><Link className="text-primary hover:underline" to={`/assets?open=${a.id}`}>{a.name}</Link> <span className="text-xs text-muted-foreground">({titleCase(a.asset_type)}, {a.classification})</span></li>)}</ul>
    </div>
  );
}
