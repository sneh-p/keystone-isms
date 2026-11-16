import { useEffect, useState } from "react";
import { Check, ExternalLink, Globe2, Lock, Plus, Trash2, Unlock, X } from "lucide-react";
import { CopyButton } from "@/components/CopyButton";
import { absoluteLink, api, upload } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Skeleton, Stat, Switch } from "@/components/ui/misc";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { Select } from "@/components/ui/select";
import { EnumSelect } from "@/components/forms";

export default function TrustCenterAdmin() {
  const { can } = useAuth();
  const { name } = usePeople();
  const { data } = useApi<any>("/trust-center");
  const vendors = useApi<any>("/vendors");
  const frameworks = useApi<any[]>("/frameworks");
  const [s, setS] = useState<any>(null);
  const [doc, setDoc] = useState<any>(null);
  const [faq, setFaq] = useState<any>(null);
  const [link, setLink] = useState<string | null>(null);
  const [subs, setSubs] = useState<Record<number, { purpose: string; location: string }>>({});
  useEffect(() => { if (data) { setS(data.settings); setSubs(Object.fromEntries(data.subprocessors.map((x: any) => [x.vendor_id, { purpose: x.purpose, location: x.location ?? "" }]))); } }, [data]);
  const inv = ["/trust-center"];
  const save = useAction((b: any) => api("/trust-center/settings", { method: "PATCH", body: b }), { success: "Saved.", invalidate: inv });
  const addDoc = useAction(async () => { const fd = new FormData(); Object.entries({ title: doc.title, kind: doc.kind, access: doc.access, description: doc.description }).forEach(([k, v]) => v && fd.append(k, v as string)); fd.append("file", doc.file); return upload("/trust-center/documents", fd); }, { success: "Document added.", invalidate: inv, onSuccess: () => setDoc(null) });
  const editDoc = useAction((v: any) => api(`/trust-center/documents/${v.id}`, { method: "PATCH", body: v.body }), { invalidate: inv });
  const addFaq = useAction(() => api("/trust-center/faqs", { body: faq }), { success: "FAQ added.", invalidate: inv, onSuccess: () => setFaq(null) });
  const delFaq = useAction((id: number) => api(`/trust-center/faqs/${id}`, { method: "DELETE" }), { invalidate: inv });
  const setSub = useAction((v: any) => api(`/trust-center/subprocessors/${v.id}`, { method: "PUT", body: { purpose: v.purpose, location: v.location } }), { success: "Subprocessor list updated.", invalidate: inv });
  const approve = useAction((id: number) => api(`/trust-center/requests/${id}/approve`, { body: {} }), { invalidate: inv, onSuccess: (r: any) => setLink(absoluteLink(r)) });
  const deny = useAction((id: number) => api(`/trust-center/requests/${id}/deny`, { method: "POST" }), { success: "Request denied.", invalidate: inv });
  const revoke = useAction((id: number) => api(`/trust-center/requests/${id}/revoke`, { method: "POST" }), { success: "Access revoked.", invalidate: inv });
  if (!data || !s) return <Skeleton className="h-96" />;
  const ed = can("trust.manage");
  const pending = data.requests.filter((r: any) => r.status === "pending");
  const passing = Object.values(data.passing_controls).flat().length;
  const url = `${window.location.origin}/trust/${s.slug}`;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Globe2} title="Trust Center" description="A public page that shows customers how you protect their data. Only controls that are implemented with current evidence appear, and they drop off automatically if they stop passing."
        actions={<><a href={`/trust/${data.settings.slug}`} target="_blank" rel="noreferrer"><Button variant="outline"><ExternalLink /> Open public page</Button></a>{ed && <Switch checked={data.settings.published} onChange={(v) => save.mutate({ published: v })} label={data.settings.published ? "Published" : "Not published"} />}</>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        <Stat label="Status" value={data.settings.published ? "Live" : "Draft"} tone={data.settings.published ? "good" : undefined} />
        <Stat label="Controls shown as passing" value={passing} />
        <Stat label="Access requests pending" value={pending.length} tone={pending.length ? "warning" : undefined} />
        <Stat label="Documents" value={data.documents.length} />
      </div>
      <Tabs tabs={[
        { value: "req", label: `Access requests${pending.length ? ` (${pending.length})` : ""}`, content: (
          <DataTable rows={data.requests} rowKey={(r: any) => r.id} empty="No access requests yet." columns={[
            { key: "w", header: "Requester", cell: (r: any) => <div><div className="font-medium">{r.name} · {r.company}</div><div className="text-xs text-muted-foreground">{r.email}</div>{r.reason && <div className="mt-1 max-w-sm text-xs">{r.reason}</div>}</div> },
            { key: "s", header: "Status", cell: (r: any) => <Badge tone={r.status === "approved" ? "good" : r.status === "pending" ? "warning" : "outline"}>{r.status}</Badge> },
            { key: "n", header: "NDA", cell: (r: any) => (r.nda_accepted_at ? <span className="text-xs">v{r.nda_version} · {r.nda_signed_name}<br />{fmtDate(r.nda_accepted_at, true)}</span> : "—") },
            { key: "e", header: "Access until", cell: (r: any) => fmtDate(r.expires_at) },
            { key: "v", header: "Downloads", cell: (r: any) => r.view_count, className: "text-right" },
            { key: "d", header: "Decided", cell: (r: any) => (r.decided_at ? `${fmtDate(r.decided_at)} · ${name(r.decided_by_id)}` : `requested ${fmtDate(r.created_at)}`) },
            { key: "x", header: "", cell: (r: any) => ed && <div className="flex justify-end gap-1">
              {r.status !== "approved" && <Button size="sm" onClick={() => approve.mutate(r.id)}><Check /> Approve</Button>}
              {r.status === "approved" && <Button size="sm" variant="outline" onClick={() => approve.mutate(r.id)}>New link</Button>}
              {r.status === "pending" && <Button size="sm" variant="ghost" onClick={() => deny.mutate(r.id)}><X /> Deny</Button>}
              {r.status === "approved" && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(r.id)}>Revoke</Button>}
            </div> },
          ]} />
        ) },
        { value: "settings", label: "Settings", content: (
          <Card><CardBody className="grid gap-4 sm:grid-cols-2">
            <Field label="Public address" hint={url}><Input value={s.slug} onChange={(e) => setS({ ...s, slug: e.target.value })} disabled={!ed} /></Field>
            <Field label="Brand colour"><div className="flex gap-2"><input type="color" value={s.brand_color} onChange={(e) => setS({ ...s, brand_color: e.target.value })} className="h-9 w-12 rounded border" disabled={!ed} /><Input value={s.brand_color} onChange={(e) => setS({ ...s, brand_color: e.target.value })} disabled={!ed} /></div></Field>
            <Field label="Headline" className="sm:col-span-2"><Input value={s.headline ?? ""} onChange={(e) => setS({ ...s, headline: e.target.value })} disabled={!ed} /></Field>
            <Field label="Overview (Markdown)" className="sm:col-span-2"><Textarea className="min-h-32" value={s.overview ?? ""} onChange={(e) => setS({ ...s, overview: e.target.value })} disabled={!ed} /></Field>
            <Field label="Security contact email"><Input value={s.contact_email ?? ""} onChange={(e) => setS({ ...s, contact_email: e.target.value })} disabled={!ed} /></Field>
            <Field label="Access lasts (days)"><Input type="number" min={1} max={365} value={s.access_days} onChange={(e) => setS({ ...s, access_days: Number(e.target.value) })} disabled={!ed} /></Field>
            <div className="space-y-2 sm:col-span-2">
              <div className="text-sm font-medium">Sections to show</div>
              <div className="flex flex-wrap gap-6">{[["show_frameworks", "Frameworks"], ["show_controls", "Passing controls"], ["show_policies", "Policy list"], ["show_subprocessors", "Subprocessors"], ["nda_required", "Require NDA for gated documents"]].map(([k, l]) => <Switch key={k} checked={s[k]} onChange={(v) => setS({ ...s, [k]: v })} label={l} disabled={!ed} />)}</div>
            </div>
            {s.show_frameworks && (
              <div className="space-y-2 sm:col-span-2">
                <div className="text-sm font-medium">Frameworks on the public page</div>
                <p className="text-xs text-muted-foreground">Frameworks appear under "Frameworks we align to". Choose "Certified" only if you hold a current certificate or attestation report; it is shown separately.</p>
                <div className="grid gap-2 sm:grid-cols-2">
                  {(frameworks.data ?? []).map((f: any) => (
                    <div key={f.code} className="flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm">
                      <span className="min-w-0 truncate">{f.name} {f.version}</span>
                      <div className="w-36 shrink-0"><Select value={s.framework_status?.[f.code] ?? "aligned"} onChange={(v) => setS({ ...s, framework_status: { ...(s.framework_status ?? {}), [f.code]: v ?? "aligned" } })}
                        options={[{ value: "aligned", label: "Aligned" }, { value: "certified", label: "Certified" }, { value: "hidden", label: "Hidden" }]} disabled={!ed} ariaLabel={`${f.name} on the public page`} /></div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {s.nda_required && <Field label={`NDA text (version ${s.nda_version}; editing it requires everyone to accept again)`} className="sm:col-span-2"><Textarea className="min-h-32" value={s.nda_text ?? ""} onChange={(e) => setS({ ...s, nda_text: e.target.value })} disabled={!ed} /></Field>}
            {ed && <div><Button loading={save.isPending} onClick={() => { const { nda_version: _v, ref: _r, ...rest } = s; save.mutate({ ...rest, contact_email: rest.contact_email || null }); }}>Save settings</Button></div>}
          </CardBody></Card>
        ) },
        { value: "docs", label: "Documents", content: (
          <>
            {ed && <Button className="mb-3" onClick={() => setDoc({ title: "", kind: "report", access: "nda", description: "", file: null })}><Plus /> Add document</Button>}
            <DataTable rows={data.documents} rowKey={(d: any) => d.id} empty="No documents yet. Add audit reports, certificates or policy PDFs." columns={[
              { key: "t", header: "Document", cell: (d: any) => <div><div className="font-medium">{d.title}</div><div className="text-xs text-muted-foreground">{d.kind}</div></div> },
              { key: "a", header: "Access", cell: (d: any) => (d.access === "public" ? <Badge tone="good"><Unlock className="size-3" /> Public</Badge> : <Badge tone="primary"><Lock className="size-3" /> On request</Badge>) },
              { key: "p", header: "Published", cell: (d: any) => <Switch checked={d.published} onChange={(v) => editDoc.mutate({ id: d.id, body: { published: v } })} disabled={!ed} /> },
              { key: "x", header: "", cell: (d: any) => ed && <Button size="sm" variant="ghost" onClick={() => editDoc.mutate({ id: d.id, body: { access: d.access === "public" ? "nda" : "public" } })}>Make {d.access === "public" ? "gated" : "public"}</Button> },
            ]} />
          </>
        ) },
        { value: "sub", label: "Subprocessors", content: (
          <Card><CardHeader title="Subprocessors" description="Publish active vendors that process customer data, with what they do and where." /><CardBody className="space-y-2">
            {(vendors.data?.vendors ?? []).filter((v: any) => v.status === "active").map((v: any) => {
              const cur = subs[v.id] ?? { purpose: "", location: "" };
              return (
                <div key={v.id} className="grid items-end gap-2 sm:grid-cols-[1fr_2fr_1fr_auto]">
                  <div className="text-sm font-medium">{v.name}</div>
                  <Input placeholder="Purpose (leave empty to hide)" value={cur.purpose} onChange={(e) => setSubs({ ...subs, [v.id]: { ...cur, purpose: e.target.value } })} disabled={!ed} />
                  <Input placeholder="Location" value={cur.location} onChange={(e) => setSubs({ ...subs, [v.id]: { ...cur, location: e.target.value } })} disabled={!ed} />
                  {ed && <Button size="sm" variant="outline" onClick={() => setSub.mutate({ id: v.id, ...cur })}>Save</Button>}
                </div>
              );
            })}
          </CardBody></Card>
        ) },
        { value: "faq", label: "FAQ", content: (
          <>
            {ed && <Button className="mb-3" onClick={() => setFaq({ question: "", answer: "", sort_order: data.faqs.length })}><Plus /> Add question</Button>}
            <div className="space-y-2">{data.faqs.map((f: any) => <Card key={f.id}><CardBody className="flex items-start justify-between gap-3"><div><div className="font-medium">{f.question}</div><p className="mt-1 text-sm text-muted-foreground">{f.answer}</p></div>{ed && <Button size="icon" variant="ghost" aria-label="Delete" onClick={() => delFaq.mutate(f.id)}><Trash2 /></Button>}</CardBody></Card>)}</div>
          </>
        ) },
      ]} />
      <Dialog open={!!doc} onOpenChange={(o) => !o && setDoc(null)} title="Add document" footer={<Button disabled={!doc?.file || !doc?.title} loading={addDoc.isPending} onClick={() => addDoc.mutate(undefined)}>Add</Button>}>
        {doc && <div className="space-y-3">
          <Field label="Title"><Input value={doc.title} onChange={(e) => setDoc({ ...doc, title: e.target.value })} /></Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Kind"><EnumSelect value={doc.kind} onChange={(v) => setDoc({ ...doc, kind: v })} values={["report", "certificate", "policy", "other"]} /></Field>
            <Field label="Access"><EnumSelect value={doc.access} onChange={(v) => setDoc({ ...doc, access: v })} values={["nda", "public"]} labels={{ nda: "On request (NDA)", public: "Public" }} /></Field>
          </div>
          <Field label="Description"><Textarea value={doc.description} onChange={(e) => setDoc({ ...doc, description: e.target.value })} /></Field>
          <input type="file" accept=".pdf,.docx,.xlsx,.png,.jpg" onChange={(e) => setDoc({ ...doc, file: e.target.files?.[0] ?? null })} className="text-sm" />
        </div>}
      </Dialog>
      <Dialog open={!!faq} onOpenChange={(o) => !o && setFaq(null)} title="FAQ" footer={<Button onClick={() => addFaq.mutate(undefined)}>Add</Button>}>
        {faq && <div className="space-y-3"><Field label="Question"><Input value={faq.question} onChange={(e) => setFaq({ ...faq, question: e.target.value })} /></Field><Field label="Answer"><Textarea value={faq.answer} onChange={(e) => setFaq({ ...faq, answer: e.target.value })} /></Field></div>}
      </Dialog>
      <Dialog open={!!link} onOpenChange={(o) => !o && setLink(null)} title="Access approved" description="Send this personal link to the requester. It is shown only once and works until it expires or you revoke it.">
        {link && <div className="flex gap-2"><Input readOnly value={link} onFocus={(e) => e.target.select()} /><CopyButton text={link} size="md" /></div>}
      </Dialog>
    </div>
  );
}
