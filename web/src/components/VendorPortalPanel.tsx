import { useState } from "react";
import { Link2, Mail, ShieldAlert, ShieldCheck } from "lucide-react";
import { absoluteLink, api, downloadUrl } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Section } from "@/components/ui/misc";
import { DateInput } from "@/components/forms";
import { CopyButton } from "@/components/CopyButton";
import { ViewAttachment, previewKind } from "@/components/DocumentViewer";

/** Staff side of the vendor portal for one questionnaire: send a link, manage it, see what the vendor uploaded. */
export function VendorPortalPanel({ questionnaireId, locked }: { questionnaireId: number; locked: boolean }) {
  const { can } = useAuth();
  const key = `/questionnaires/${questionnaireId}/portal`;
  const { data } = useApi<any>(key);
  const [form, setForm] = useState({ contact_name: "", contact_email: "", expires_on: null as string | null });
  const [created, setCreated] = useState<string | null>(null);
  const emailReady = useApi<{ ready: boolean }>("/email-status").data?.ready;
  const create = useAction((send_email: boolean) => api(`/questionnaires/${questionnaireId}/portal-link`, { body: { contact_name: form.contact_name || null, contact_email: form.contact_email || null, expires_at: form.expires_on ? `${form.expires_on}T00:00:00Z` : null, send_email } }),
    { success: (r: any) => (r.emailed_to ? `Link emailed to ${r.emailed_to}.` : "Link created. Copy it now; it can't be shown again."), invalidate: [key], onSuccess: (r: any) => setCreated(absoluteLink(r)) });
  const revoke = useAction((id: number) => api(`/portal-links/${id}/revoke`, { method: "POST" }), { success: "Link revoked.", invalidate: [key] });
  const expiry = useAction((v: { id: number; date: string | null }) => api(`/portal-links/${v.id}`, { method: "PATCH", body: { expires_at: v.date ? `${v.date}T00:00:00Z` : null } }), { success: "Expiry updated.", invalidate: [key] });
  if (!data) return null;
  const active = data.links.find((l: any) => !l.revoked_at);
  const editable = can("vendor.write") && !locked;
  return (
    <Section title="Vendor portal">
      <p className="mb-3 text-sm text-muted-foreground">Send the vendor a link to answer this questionnaire and upload documents themselves. Files are checked and virus-scanned before they are stored.</p>
      <p className="mb-3 flex items-center gap-1.5 text-xs">
        {data.scanner_ok ? <><ShieldCheck className="size-4 text-good" aria-hidden /> Virus scanner available</> : <><ShieldAlert className="size-4 text-critical" aria-hidden /> <span className="text-critical">Virus scanner unavailable: vendor uploads are refused until it is back.</span></>}
      </p>
      {created && (
        <div className="mb-3 rounded-md border border-primary/40 bg-primary/5 p-3 text-sm">
          <div className="mb-1 font-medium">Send this link to the vendor</div>
          <div className="flex items-center gap-2"><code className="min-w-0 flex-1 truncate text-xs">{created}</code><CopyButton text={created} /></div>
          <p className="mt-1 text-xs text-muted-foreground">Shown once. Anyone with the link can answer this questionnaire, so send it only to your contact.</p>
        </div>
      )}
      {data.links.length > 0 && (
        <ul className="mb-3 divide-y rounded-md border text-sm">
          {data.links.map((l: any) => (
            <li key={l.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
              <Link2 className="size-4 text-muted-foreground" aria-hidden />
              <span className="min-w-0 flex-1">{l.contact_name || l.contact_email || "Link"} <span className="text-xs text-muted-foreground">created {fmtDate(l.created_at)}{l.last_used_at ? ` · last used ${fmtDate(l.last_used_at, true)}` : " · not used yet"}</span></span>
              {l.revoked_at ? <Badge tone="outline">Revoked</Badge> : l.expires_at && new Date(l.expires_at) <= new Date() ? <Badge tone="warning">Expired</Badge> : <Badge tone="good">Active</Badge>}
              {!l.revoked_at && editable && (
                <>
                  <div className="w-40"><DateInput value={l.expires_at ? l.expires_at.slice(0, 10) : null} onChange={(v) => expiry.mutate({ id: l.id, date: v })} ariaLabel="Link expires on (empty: never)" /></div>
                  <Button size="sm" variant="ghost" onClick={() => { if (confirm("Revoke this link? The vendor will no longer be able to open it.")) revoke.mutate(l.id); }}>Revoke</Button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {editable && (
        <div className="space-y-2 rounded-lg border border-dashed p-3">
          <div className="grid gap-2 sm:grid-cols-3">
            <Field label="Contact name"><Input value={form.contact_name} onChange={(e) => setForm({ ...form, contact_name: e.target.value })} /></Field>
            <Field label="Contact email"><Input value={form.contact_email} onChange={(e) => setForm({ ...form, contact_email: e.target.value })} /></Field>
            <Field label="Expires (optional)" hint="Empty: the link never expires."><DateInput value={form.expires_on} onChange={(v) => setForm({ ...form, expires_on: v })} /></Field>
          </div>
          <div className="flex flex-wrap gap-2">
            {emailReady && <Button size="sm" disabled={!form.contact_email} loading={create.isPending} onClick={() => create.mutate(true)}><Mail /> {active ? "Email a new link (replaces the current one)" : "Email link to the contact"}</Button>}
            <Button size="sm" variant={emailReady ? "outline" : "default"} loading={create.isPending} onClick={() => create.mutate(false)}><Link2 /> {active ? "Create a new link (replaces the current one)" : "Create vendor link"}</Button>
          </div>
        </div>
      )}
      {data.files.length > 0 && (
        <div className="mt-4">
          <div className="mb-1 text-sm font-medium">Files from the vendor ({data.files.length})</div>
          <ul className="divide-y rounded-md border text-sm">
            {data.files.map((f: any) => (
              <li key={f.id} className="flex items-center justify-between gap-2 px-3 py-1.5">
                <span className="min-w-0 truncate">{f.filename} <span className="text-xs text-muted-foreground">{Math.ceil(f.size / 1024)} KB · {fmtDate(f.created_at, true)}</span></span>
                <span className="flex items-center">
                  {previewKind(f.filename) && <ViewAttachment id={f.id} filename={f.filename} size="icon" />}
                  <a href={downloadUrl(`/attachments/${f.id}`)} className="text-xs text-primary hover:underline">Download</a>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Section>
  );
}
