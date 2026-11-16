import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ClipboardList, Send } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, PageHeader, Section, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { DateInput } from "@/components/forms";

export default function Questionnaires() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any[]>("/questionnaires");
  const tpls = useApi<any[]>("/questionnaire-templates");
  const vendors = useApi<any>("/vendors");
  const [send, setSend] = useState<any>(null);
  const load = useAction(() => api("/questionnaire-templates/load-defaults", { method: "POST" }), { success: "Template loaded.", invalidate: ["/questionnaire"] });
  const doSend = useAction((b: any) => api("/questionnaires", { body: b }), { success: "Questionnaire recorded as sent.", invalidate: ["/questionnaires", "/vendors"], onSuccess: () => setSend(null) });
  if (!data || !tpls.data) return <Skeleton className="h-96" />;
  const vname = new Map((vendors.data?.vendors ?? []).map((v: any) => [v.id, v.name]));
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ClipboardList} title="Vendor questionnaires" description="Send a template, record the vendor's answers, and review the findings."
        actions={can("vendor.write") && (tpls.data.length ? <Button onClick={() => setSend({ vendor_id: null, template_id: String(tpls.data![0].id), due_date: null })}><Send /> Send questionnaire</Button> : <Button onClick={() => load.mutate(undefined)} loading={load.isPending}>Load baseline template</Button>)} />
      {data.length === 0 ? <Empty icon={ClipboardList} title="No questionnaires yet">Send the Keystone baseline security questionnaire to a vendor.</Empty> : (
        <DataTable rows={data} rowKey={(q: any) => q.id} onRowClick={(q: any) => setParams({ open: String(q.id) })} search={(q: any) => `${vname.get(q.vendor_id)} ${q.template_name}`} columns={[
          { key: "v", header: "Vendor", cell: (q: any) => <span className="font-medium">{vname.get(q.vendor_id) as string}</span>, sort: (q: any) => String(vname.get(q.vendor_id)) },
          { key: "t", header: "Template", cell: (q: any) => q.template_name },
          { key: "s", header: "Status", cell: (q: any) => <StatusBadge status={q.status} />, sort: (q: any) => q.status },
          { key: "due", header: "Due", cell: (q: any) => fmtDate(q.due_date), sort: (q: any) => q.due_date ?? "" },
          { key: "sc", header: "Score", cell: (q: any) => (q.score !== null ? <span className="font-semibold tabular-nums">{Math.round(q.score)}%</span> : "—"), sort: (q: any) => q.score ?? -1 },
        ]} />
      )}
      <Dialog open={!!send} onOpenChange={(o) => !o && setSend(null)} title="Send a questionnaire" footer={<Button loading={doSend.isPending} disabled={!send?.vendor_id} onClick={() => doSend.mutate({ vendor_id: Number(send.vendor_id), template_id: Number(send.template_id), due_date: send.due_date })}>Mark as sent</Button>}>
        {send && <div className="space-y-4">
          <Field label="Vendor"><Select value={send.vendor_id} onChange={(v) => setSend({ ...send, vendor_id: v })} options={(vendors.data?.vendors ?? []).map((v: any) => ({ value: String(v.id), label: v.name }))} /></Field>
          <Field label="Template"><Select value={send.template_id} onChange={(v) => setSend({ ...send, template_id: v })} options={tpls.data.map((t) => ({ value: String(t.id), label: `${t.name} v${t.version}` }))} /></Field>
          <Field label="Due date" hint="Defaults to 30 days."><DateInput value={send.due_date} onChange={(v) => setSend({ ...send, due_date: v })} /></Field>
        </div>}
      </Dialog>
      {params.get("open") && <Answers id={Number(params.get("open"))} vendor={(id: number) => vname.get(id) as string} onClose={() => setParams({})} />}
    </div>
  );
}

const OPTS: Record<string, string[]> = { yn: ["yes", "no", "na"], ynp: ["yes", "partial", "no", "na"] };

function Answers({ id, vendor, onClose }: { id: number; vendor: (id: number) => string; onClose: () => void }) {
  const { can } = useAuth();
  const { data } = useApi<any>(`/questionnaires/${id}`);
  const [resp, setResp] = useState<any>({});
  const [notes, setNotes] = useState("");
  useEffect(() => { if (data) setResp(data.responses ?? {}); }, [data]);
  const save = useAction((complete: boolean) => api(`/questionnaires/${id}/responses`, { body: { responses: resp, complete } }), { success: "Answers saved.", invalidate: ["/questionnaires", "/vendors"] });
  const review = useAction(() => api(`/questionnaires/${id}/review`, { body: { notes } }), { success: "Review completed.", invalidate: ["/questionnaires"] });
  const locked = !data || data.status === "reviewed" || !can("vendor.write");
  let section = "";
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data ? `${vendor(data.vendor_id)} · ${data.template_name}` : "Loading…"} subtitle={data && <span className="flex items-center gap-2"><StatusBadge status={data.status} />{data.score !== null && <Badge tone="primary">Score {Math.round(data.score)}%</Badge>}</span>}
      actions={!locked && <><Button variant="outline" size="sm" loading={save.isPending} onClick={() => save.mutate(false)}>Save</Button>{["sent", "draft"].includes(data.status) && <Button size="sm" onClick={() => save.mutate(true)}>Mark received</Button>}</>}>
      {!data ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          {data.findings.length > 0 && (
            <Section title={`Findings (${data.findings.length})`}>
              <ul className="space-y-2">{data.findings.map((f: any) => <li key={f.id} className="rounded-md border px-3 py-2 text-sm"><div className="flex items-center gap-2"><Badge tone={f.answer === "no" ? "critical" : "warning"}>{f.answer}</Badge>{f.control && <Badge tone="primary">{f.control}</Badge>}</div><p className="mt-1">{f.question}</p>{f.comment && <p className="mt-1 text-muted-foreground">“{f.comment}”</p>}</li>)}</ul>
            </Section>
          )}
          <div className="space-y-3">
            {data.questions.map((q: any) => {
              const head = q.section !== section ? (section = q.section) : null;
              const cur = resp[q.id] ?? {};
              const set = (k: string, v: any) => setResp((p: any) => ({ ...p, [q.id]: { ...(p[q.id] ?? {}), [k]: v } }));
              return (
                <div key={q.id}>
                  {head && <h4 className="mb-2 mt-5 text-sm font-semibold uppercase tracking-wide text-muted-foreground">{head}</h4>}
                  <div className="rounded-lg border p-3">
                    <p className="text-sm">{q.text}{q.required && <span className="text-critical"> *</span>}</p>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      {q.type !== "text" && OPTS[q.type].map((o) => (
                        <button key={o} disabled={locked} onClick={() => set("answer", cur.answer === o ? null : o)} className={`rounded-md border px-3 py-1 text-xs font-medium capitalize transition-colors ${cur.answer === o ? "border-primary bg-primary text-primary-foreground" : "hover:bg-muted"}`}>{o === "na" ? "N/A" : o}</button>
                      ))}
                      <Input className="h-8 min-w-48 flex-1" placeholder={q.type === "text" ? "Answer" : "Comment"} value={cur.comment ?? ""} onChange={(e) => set("comment", e.target.value)} disabled={locked} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          {data.status === "received" && can("vendor.write") && (
            <Section title="Review">
              <Textarea placeholder="Review notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
              <Button className="mt-2" loading={review.isPending} onClick={() => review.mutate(undefined)}>Complete review</Button>
            </Section>
          )}
          {data.review_notes && <p className="rounded-md bg-muted p-3 text-sm">Review notes: {data.review_notes}</p>}
        </div>
      )}
    </Sheet>
  );
}
