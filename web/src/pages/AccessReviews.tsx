import { useState } from "react";
import { useSearchParams } from "react-router";
import { Download, Plus, UserCheck } from "lucide-react";
import { api, downloadUrl } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { PageHeader, Progress, Skeleton, Switch } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { DateInput, OwnerSelect } from "@/components/forms";

const DECISION_TONE: Record<string, any> = { keep: "good", revoke: "critical", change: "warning" };
const inv = ["/access-reviews", "/dashboard"];

/** Access review campaigns: each reviewer confirms or revokes the access of the people they're responsible for. */
export default function AccessReviews() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const open = params.get("open");
  const { data } = useApi<any[]>("/access-reviews");
  const [start, setStart] = useState<any>(null);
  const create = useAction(() => api<any>("/access-reviews", { body: { title: start.title, due_date: start.due_date, owner_id: start.owner_id, repeat_months: start.repeat_months ? Number(start.repeat_months) : null, sources: [...(start.keystone ? ["keystone"] : []), ...(start.identities ? ["identities"] : [])] } }),
    { success: "Campaign started. Reviewers see their items in My tasks.", invalidate: inv, onSuccess: (r: any) => { setStart(null); setParams({ open: String(r.id) }); } });
  if (!data) return <Skeleton className="h-96" />;
  const today = new Date().toISOString().slice(0, 10);
  return (
    <div className="animate-fade-in">
      <PageHeader icon={UserCheck} title="Access reviews" description="Periodic confirmation of who has access: managers keep, revoke or change each account, and the result becomes evidence."
        actions={can("access_review.manage") && <Button onClick={() => setStart({ title: `Access review ${new Date().getFullYear()} Q${Math.floor(new Date().getMonth() / 3) + 1}`, due_date: null, owner_id: null, keystone: true, identities: true, repeat_months: "3" })}><Plus /> Start a campaign</Button>} />
      <DataTable rows={data} rowKey={(r: any) => r.id} onRowClick={(r: any) => setParams({ open: String(r.id) })} empty="No campaigns yet. Review access at least once a year, privileged access more often."
        columns={[
          { key: "t", header: "Campaign", cell: (r: any) => <div><div className="font-medium">{r.title}</div><div className="text-xs text-muted-foreground">{r.sources.map((x: string) => (x === "keystone" ? "Keystone accounts" : "Connected identities")).join(" + ")} · owner {name(r.owner_id)}</div></div> },
          { key: "p", header: "Progress", cell: (r: any) => <div className="w-40"><Progress label={`${r.title} progress`} value={r.total ? Math.round((100 * r.decided) / r.total) : 0} tone={r.decided === r.total ? "good" : "primary"} /><div className="mt-1 text-xs text-muted-foreground">{r.decided}/{r.total} decided{r.revoke ? ` · ${r.revoke} to revoke` : ""}{r.change ? ` · ${r.change} to change` : ""}</div></div> },
          { key: "d", header: "Due", sort: (r: any) => r.due_date, cell: (r: any) => <span className={r.status === "open" && r.due_date < today ? "font-medium text-critical" : undefined}>{fmtDate(r.due_date)}</span> },
          { key: "s", header: "Status", cell: (r: any) => <Badge tone={r.status === "completed" ? "good" : "primary"}>{titleCase(r.status)}</Badge> },
        ]} />
      {open && <Campaign id={Number(open)} review={data.find((r: any) => r.id === Number(open))} onClose={() => setParams({})} />}
      <Dialog open={!!start} onOpenChange={(o) => !o && setStart(null)} title="Start an access review" description="Keystone lists every account in scope and sends each one to the person's manager (from People), or to the campaign owner."
        footer={<Button disabled={!start?.title?.trim() || !start?.due_date || (!start?.keystone && !start?.identities)} loading={create.isPending} onClick={() => create.mutate(undefined)}>Start campaign</Button>}>
        {start && <div className="space-y-4">
          <Field label="Title" required><Input value={start.title} onChange={(e) => setStart({ ...start, title: e.target.value })} /></Field>
          <Switch checked={start.keystone} onChange={(v) => setStart({ ...start, keystone: v })} label="Keystone accounts and roles" />
          <Switch checked={start.identities} onChange={(v) => setStart({ ...start, identities: v })} label="Accounts from connected identity sources (Attack surface)" />
          <Field label="Due" required><DateInput value={start.due_date} onChange={(v) => setStart({ ...start, due_date: v })} /></Field>
          <Field label="Repeat" hint="The next campaign starts by itself, with 30 days to complete."><Select ariaLabel="Repeat" value={start.repeat_months} onChange={(v) => setStart({ ...start, repeat_months: v })} allowEmpty emptyLabel="Don't repeat" options={[{ value: "3", label: "Every 3 months" }, { value: "6", label: "Every 6 months" }, { value: "12", label: "Every year" }]} /></Field>
          <Field label="Owner" hint="Defaults to you. Reviews items nobody else can, and receives the follow-up task."><OwnerSelect value={start.owner_id} onChange={(v) => setStart({ ...start, owner_id: v })} emptyLabel="Me" /></Field>
        </div>}
      </Dialog>
    </div>
  );
}

function Campaign({ id, review, onClose }: { id: number; review: any; onClose: () => void }) {
  const { can, me } = useAuth();
  const { name } = usePeople();
  const [mine, setMine] = useState(!can("access_review.manage"));
  const { data } = useApi<any[]>(`/access-reviews/${id}/items${mine ? "?mine=true" : ""}`);
  const [d, setD] = useState<any>(null);
  const decide = useAction((v: any) => api(`/access-reviews/items/${v.id}/decide`, { body: { decision: v.decision, comment: v.comment || null } }), { invalidate: inv, onSuccess: () => setD(null) });
  const apply = useAction((iid: number) => api(`/access-reviews/items/${iid}/apply`, { method: "POST" }), { success: "Account deactivated.", invalidate: inv });
  const complete = useAction(() => api(`/access-reviews/${id}/complete`, { method: "POST" }), { success: "Campaign completed. Evidence filed; follow-up task created if needed.", invalidate: [...inv, "/tasks", "/evidence"] });
  const isOpen = review?.status === "open";
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={review?.title ?? "Access review"} subtitle={review && `Due ${fmtDate(review.due_date)} · ${review.decided}/${review.total} decided`}
      actions={review && <>
        <a href={downloadUrl(`/access-reviews/${review.id}/export.xlsx`)}><Button size="sm" variant="outline"><Download /> Export</Button></a>
        {isOpen && can("access_review.manage") && <Button size="sm" disabled={review.decided !== review.total} loading={complete.isPending} onClick={() => complete.mutate(undefined)}>Complete campaign</Button>}
      </>}>
      <div className="space-y-3">
        {can("access_review.manage") && <Switch checked={mine} onChange={setMine} label="Only items I review" />}
        {!data ? <Skeleton className="h-64" /> : (
          <DataTable rows={data} rowKey={(i: any) => i.id} search={(i: any) => i.subject} empty={mine ? "Nothing for you to review here." : "No items."} columns={[
            { key: "s", header: "Account", cell: (i: any) => <div><div className="font-medium">{i.subject}</div><div className="text-xs text-muted-foreground">{i.access}</div></div> },
            { key: "r", header: "Reviewer", cell: (i: any) => name(i.reviewer_id) },
            { key: "d", header: "Decision", cell: (i: any) => i.decision ? <div><Badge tone={DECISION_TONE[i.decision]}>{titleCase(i.decision)}</Badge>{i.comment && <div className="text-xs text-muted-foreground">{i.comment}</div>}{i.actioned_at && <div className="text-xs">Applied {fmtDate(i.actioned_at)}</div>}</div>
              : isOpen && i.reviewer_id === me?.id ? <span className="flex flex-wrap gap-1">
                <Button size="sm" variant="outline" onClick={() => decide.mutate({ id: i.id, decision: "keep" })}>Keep</Button>
                <Button size="sm" variant="ghost" onClick={() => setD({ id: i.id, subject: i.subject, decision: "revoke", comment: "" })}>Revoke</Button>
                <Button size="sm" variant="ghost" onClick={() => setD({ id: i.id, subject: i.subject, decision: "change", comment: "" })}>Change</Button>
              </span> : <span className="text-xs text-muted-foreground">Waiting</span> },
            { key: "a", header: "", cell: (i: any) => i.decision === "revoke" && i.source === "keystone" && !i.actioned_at && can("users.manage") && i.user_id !== me?.id
              ? <Button size="sm" variant="outline" onClick={() => { if (confirm(`Deactivate ${i.subject}? Their sessions end now.`)) apply.mutate(i.id); }}>Deactivate account</Button> : null },
          ]} />
        )}
      </div>
      <Dialog open={!!d} onOpenChange={(o) => !o && setD(null)} title={d?.decision === "revoke" ? "Revoke access" : "Change access"} description={d?.subject}
        footer={<Button disabled={!d?.comment?.trim()} loading={decide.isPending} onClick={() => decide.mutate(d)}>Record decision</Button>}>
        {d && <Field label={d.decision === "revoke" ? "Why" : "What should change"} required><Input value={d.comment} onChange={(e) => setD({ ...d, comment: e.target.value })} /></Field>}
      </Dialog>
    </Sheet>
  );
}
