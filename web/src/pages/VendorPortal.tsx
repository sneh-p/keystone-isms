import { useEffect, useRef, useState } from "react";
import { CheckCircle2, ClipboardList, Download, FileText, Trash2, Upload } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, fragmentParam, saveDownload, upload } from "@/lib/api";
import { cn, fmtDate } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";

const LABEL: Record<string, string> = { yes: "Yes", no: "No", partial: "Partly", na: "Not applicable" };

/**
 * Public page for a vendor answering one questionnaire. The access token comes from the URL fragment (never sent to
 * the server as part of a URL) and is sent only in the X-Vendor-Token header.
 */
export default function VendorPortal() {
  const [token, setToken] = useState(() => fragmentParam("token"));
  useEffect(() => {
    const fn = () => setToken(fragmentParam("token"));
    window.addEventListener("hashchange", fn);
    return () => window.removeEventListener("hashchange", fn);
  }, []);
  const auth = token ? { "X-Vendor-Token": token } : undefined;
  const qc = useQueryClient();
  const { data, error, isLoading } = useQuery<any>({ queryKey: ["vendor-portal", token], queryFn: () => api("/public/vendor-portal", { headers: auth }), enabled: !!token, retry: false });
  const [resp, setResp] = useState<Record<string, { answer?: string | null; comment?: string | null }>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  useEffect(() => { if (data) { setResp(data.responses ?? {}); setDirty(false); } }, [data]);
  useEffect(() => { document.title = data ? `${data.title} · ${data.company}` : "Vendor questionnaire"; }, [data]);

  const run = async (what: string, fn: () => Promise<any>, ok?: string) => {
    setBusy(what);
    try {
      const r = await fn();
      qc.setQueryData(["vendor-portal", token], r);
      if (ok) toast.success(ok);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  const save = (submit: boolean) => run(submit ? "submit" : "save", () => api("/public/vendor-portal", { method: "PUT", body: { responses: resp, submit }, headers: auth }), submit ? "Submitted. Thank you." : "Saved.");
  const send = (f: File | undefined) => {
    if (!f) return;
    const fd = new FormData();
    fd.append("file", f);
    void run("upload", () => upload("/public/vendor-portal/files", fd, "POST", auth), `${f.name} uploaded.`);
  };

  if (!token) return <Shell><Message title="Link incomplete">Open the full link you were sent. It ends with a long code after “#token=”.</Message></Shell>;
  if (isLoading) return <Shell><Skeleton className="h-96" /></Shell>;
  if (error || !data) return <Shell><Message title="This link can't be opened">{(error as Error)?.message ?? "Ask your contact for a new link."}</Message></Shell>;

  const sections = [...new Set(data.questions.map((q: any) => q.section))] as string[];
  const answered = data.questions.filter((q: any) => resp[q.id]?.answer || (q.type === "text" && resp[q.id]?.comment)).length;
  const missing = data.questions.filter((q: any) => q.required && !resp[q.id]?.answer).length;
  return (
    <Shell company={data.company}>
      <div className="rounded-xl border bg-card p-6 shadow-sm">
        <div className="flex items-center gap-2 text-sm text-muted-foreground"><ClipboardList className="size-4" aria-hidden /> Security questionnaire for {data.vendor}</div>
        <h1 className="mt-2 text-2xl font-semibold">{data.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">Requested by {data.company}{data.due_date ? ` · due ${fmtDate(data.due_date)}` : ""}. {data.editable ? "Your answers are saved when you choose Save; you can come back to this link later." : "Submitted: this questionnaire is now read-only."}</p>
        {!data.editable && <p className="mt-3 flex items-center gap-2 rounded-md bg-good/10 px-3 py-2 text-sm"><CheckCircle2 className="size-4 text-good" aria-hidden /> Thank you. {data.company} has received your answers.</p>}
        <div className="mt-3 text-sm"><span className="font-medium">{answered}</span> of {data.questions.length} answered</div>
      </div>

      {sections.map((sec) => (
        <section key={sec} className="rounded-xl border bg-card p-6 shadow-sm" aria-labelledby={`sec-${sec}`}>
          <h2 id={`sec-${sec}`} className="text-lg font-semibold">{sec}</h2>
          <div className="mt-4 space-y-5">
            {data.questions.filter((q: any) => q.section === sec).map((q: any) => {
              const cur = resp[q.id] ?? {};
              const set = (k: "answer" | "comment", v: string | null) => { setResp((p) => ({ ...p, [q.id]: { ...(p[q.id] ?? {}), [k]: v } })); setDirty(true); };
              const opts: string[] | null = data.answer_options[q.type];
              return (
                <fieldset key={q.id} disabled={!data.editable} className="space-y-2">
                  <legend className="text-sm">{q.text}{q.required && <span className="text-critical"> *<span className="sr-only">(required)</span></span>}</legend>
                  {opts && (
                    <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Answer">
                      {opts.map((o) => (
                        <button key={o} type="button" role="radio" aria-checked={cur.answer === o} onClick={() => set("answer", cur.answer === o ? null : o)}
                          className={cn("rounded-md border px-3 py-1.5 text-sm transition-colors disabled:opacity-60", cur.answer === o ? "border-primary bg-primary text-primary-foreground" : "hover:bg-muted")}>{LABEL[o] ?? o}</button>
                      ))}
                    </div>
                  )}
                  <Textarea aria-label={opts ? "Comment (optional)" : "Answer"} placeholder={opts ? "Comment (optional)" : "Your answer"} className="min-h-16" maxLength={10000}
                    value={(opts ? cur.comment : cur.comment ?? cur.answer) ?? ""} onChange={(e) => (opts ? set("comment", e.target.value) : (set("answer", e.target.value || null), set("comment", null)))} />
                </fieldset>
              );
            })}
          </div>
        </section>
      ))}

      <section className="rounded-xl border bg-card p-6 shadow-sm" aria-labelledby="files">
        <h2 id="files" className="text-lg font-semibold">Supporting documents</h2>
        <p className="mt-1 text-sm text-muted-foreground">For example certificates, audit reports or policies. {data.limits.types.map((t: string) => t.toUpperCase()).join(", ")}; up to {data.limits.max_mb} MB each and {data.limits.max_files} files. Every file is virus-scanned.</p>
        {data.files.length > 0 && (
          <ul className="mt-3 divide-y rounded-md border text-sm">
            {data.files.map((f: any) => (
              <li key={f.id} className="flex items-center justify-between gap-2 px-3 py-2">
                <span className="flex min-w-0 items-center gap-2"><FileText className="size-4 shrink-0 text-muted-foreground" aria-hidden /><span className="truncate">{f.filename}</span><span className="text-xs text-muted-foreground">{Math.ceil(f.size / 1024)} KB</span></span>
                <span className="flex items-center">
                  <Button size="icon" variant="ghost" aria-label={`Download ${f.filename}`} onClick={() => saveDownload(`/public/vendor-portal/files/${f.id}`, auth).catch((e) => toast.error(e.message))}><Download /></Button>
                  {data.editable && <Button size="icon" variant="ghost" aria-label={`Remove ${f.filename}`} onClick={() => void run("delete", () => api(`/public/vendor-portal/files/${f.id}`, { method: "DELETE", headers: auth }))}><Trash2 /></Button>}
                </span>
              </li>
            ))}
          </ul>
        )}
        {data.editable && (
          <>
            <input ref={file} type="file" className="sr-only" aria-label="Choose a document" accept={data.limits.types.map((t: string) => `.${t}`).join(",")} onChange={(e) => { send(e.target.files?.[0]); e.target.value = ""; }} />
            <Button className="mt-3" variant="outline" loading={busy === "upload"} onClick={() => file.current?.click()}><Upload /> Upload a document</Button>
          </>
        )}
      </section>

      {data.editable && (
        <div className="sticky bottom-0 -mx-4 flex flex-wrap items-center gap-2 border-t bg-background/95 px-4 py-3 backdrop-blur sm:mx-0 sm:rounded-xl sm:border">
          <Button variant="outline" loading={busy === "save"} onClick={() => void save(false)}>Save</Button>
          <Button loading={busy === "submit"} disabled={missing > 0} onClick={() => { if (confirm("Submit your answers? You won't be able to change them afterwards.")) void save(true); }}>Submit</Button>
          <span className="text-xs text-muted-foreground">{missing > 0 ? `${missing} required question${missing === 1 ? "" : "s"} still to answer.` : "All required questions answered."}{dirty ? " Unsaved changes." : ""}</span>
        </div>
      )}
    </Shell>
  );
}

function Shell({ children, company }: { children: React.ReactNode; company?: string }) {
  return (
    <div className="min-h-full bg-background">
      <header className="border-b bg-card"><div className="mx-auto flex h-14 max-w-3xl items-center gap-2 px-4 text-sm font-semibold">{company ? `${company} · ` : ""}Vendor questionnaire</div></header>
      <main className="mx-auto max-w-3xl space-y-5 px-4 py-6">{children}</main>
    </div>
  );
}

function Message({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="rounded-xl border bg-card p-8 text-center shadow-sm"><h1 className="text-lg font-semibold">{title}</h1><p className="mt-2 text-sm text-muted-foreground">{children}</p></div>;
}
