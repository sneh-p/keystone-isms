import { useEffect, useState, type FormEvent } from "react";
import { useParams, useSearchParams } from "react-router";
import { BadgeCheck, CheckCircle2, ChevronDown, Download, FileText, Lock, Mail, ShieldCheck } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, fragmentParam, saveDownload } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { cn, fmtDate } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { Markdown } from "@/components/Markdown";

function readToken(param: string | null, slug: string): string | null {
  try {
    if (param) sessionStorage.setItem(`trust-${slug}`, param);
    return param ?? sessionStorage.getItem(`trust-${slug}`);
  } catch {
    return param;
  }
}

export default function PublicTrust() {
  const { slug = "" } = useParams();
  const [params, setParams] = useSearchParams();
  // SC-CRY-005: links carry the token after '#', which never reaches the server; ?access= is accepted for old links.
  const [token, setToken] = useState(() => readToken(fragmentParam("access") ?? params.get("access"), slug));
  useEffect(() => {
    if (params.get("access")) setParams({}, { replace: true });
    const fromFragment = () => {
      const t = fragmentParam("access");
      if (t) setToken(readToken(t, slug)); // also when the link is opened in a tab already on this page
      if (window.location.hash) window.history.replaceState(null, "", window.location.pathname + window.location.search); // keep it out of the address bar
    };
    fromFragment();
    window.addEventListener("hashchange", fromFragment);
    return () => window.removeEventListener("hashchange", fromFragment);
  }, [params, setParams, slug]);
  const auth = token ? { "X-Trust-Access": token } : undefined;
  const { data, isError, error } = useApi<any>(`/public/trust/${slug}`);
  const grant = useQuery<any>({ queryKey: [`/public/trust/${slug}/access`, token], queryFn: () => api(`/public/trust/${slug}/access`, { headers: auth }), enabled: !!token });
  const [req, setReq] = useState({ name: "", email: "", company: "", reason: "", website: "" });
  const [sent, setSent] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [signed, setSigned] = useState("");
  const [faqOpen, setFaqOpen] = useState<number | null>(0);
  if (isError) return <div className="grid min-h-full place-items-center p-6 text-center"><div><ShieldCheck className="mx-auto mb-3 size-10 text-muted-foreground" /><p className="text-muted-foreground">{(error as Error).message}</p></div></div>;
  if (!data) return <div className="mx-auto max-w-5xl p-8"><Skeleton className="h-64" /></div>;
  const brand = data.brand_color;
  const certified = (data.frameworks ?? []).filter((f: any) => f.status === "certified");
  const aligned = (data.frameworks ?? []).filter((f: any) => f.status !== "certified");
  const access = grant.data && (!grant.data.nda_required || grant.data.nda_ok);
  const request = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try { await api(`/public/trust/${slug}/requests`, { body: req }); setSent(true); } catch (x: any) { setErr(x.message); }
  };
  const acceptNda = async () => { await api(`/public/trust/${slug}/access/nda`, { body: { signed_name: signed }, headers: auth }); await grant.refetch(); };
  const download = (id: string) => { saveDownload(`/public/trust/${slug}/documents/${id}`, auth).catch((x: Error) => toast.error(x.message)); };
  return (
    <div className="min-h-full bg-background">
      <header style={{ background: `linear-gradient(135deg, ${brand}, ${brand}cc)` }} className="text-white">
        <div className="mx-auto max-w-5xl px-6 pb-14 pt-10">
          <div className="flex items-center gap-2 text-sm text-white/80"><ShieldCheck className="size-4" /> Trust Center</div>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.02em] sm:text-4xl">{data.headline || `${data.company} Trust Center`}</h1>
          <p className="mt-2 max-w-2xl text-white/85">How {data.company} protects your data. Updated {fmtDate(data.updated_at)}.</p>
          {certified.length > 0 && <div className="mt-6 flex flex-wrap gap-2">{certified.map((f: any) => <span key={f.code} className="inline-flex items-center gap-1.5 rounded-full bg-white/15 px-3 py-1 text-sm backdrop-blur"><BadgeCheck className="size-4" aria-hidden />Certified: {f.name}</span>)}</div>}
        </div>
      </header>
      <main className="mx-auto -mt-8 max-w-5xl space-y-6 px-6 pb-16">
        {data.overview && <section className="rounded-xl border bg-card p-6 shadow-card"><Markdown>{data.overview}</Markdown></section>}
        {aligned.length > 0 && (
          <section className="rounded-xl border bg-card p-6 shadow-card">
            <h2 className="text-lg font-semibold">Frameworks we align to</h2>
            <p className="mt-1 text-sm text-muted-foreground">Our controls are mapped to these frameworks. Alignment is not a certification{certified.length ? "; certifications are shown at the top of this page" : ""}.</p>
            <ul className="mt-4 flex flex-wrap gap-2">{aligned.map((f: any) => <li key={f.code} className="rounded-full border px-3 py-1 text-sm">{f.name}</li>)}</ul>
          </section>
        )}
        {data.controls && Object.keys(data.controls).length > 0 && (
          <section className="rounded-xl border bg-card p-6 shadow-card">
            <h2 className="text-lg font-semibold">Security controls in place</h2>
            <p className="mt-1 text-sm text-muted-foreground">Controls that are implemented and backed by current evidence. This list updates automatically.</p>
            <div className="mt-5 grid gap-6 sm:grid-cols-2">
              {Object.entries(data.controls).map(([domain, items]: any) => (
                <div key={domain}>
                  <div className="mb-2 text-sm font-semibold">{domain}</div>
                  <ul className="space-y-1.5">{items.map((t: string) => <li key={t} className="flex items-start gap-2 text-sm"><CheckCircle2 className="mt-0.5 size-4 shrink-0" style={{ color: brand }} />{t}</li>)}</ul>
                </div>
              ))}
            </div>
          </section>
        )}
        <div className="grid gap-6 lg:grid-cols-2">
          {data.documents?.length > 0 && (
            <section className="rounded-xl border bg-card p-6 shadow-card">
              <h2 className="text-lg font-semibold">Documents</h2>
              <ul className="mt-4 divide-y">
                {data.documents.map((d: any) => (
                  <li key={d.id} className="flex items-center justify-between gap-3 py-3 text-sm">
                    <span className="flex items-start gap-2"><FileText className="mt-0.5 size-4 shrink-0 text-muted-foreground" /><span><span className="font-medium">{d.title}</span>{d.description && <span className="block text-xs text-muted-foreground">{d.description}</span>}</span></span>
                    {d.access === "public" || access ? <Button size="sm" variant="outline" onClick={() => download(d.id)}><Download /> Download</Button> : <span className="flex items-center gap-1 text-xs text-muted-foreground"><Lock className="size-3.5" /> On request</span>}
                  </li>
                ))}
              </ul>
            </section>
          )}
          {data.policies?.length > 0 && (
            <section className="rounded-xl border bg-card p-6 shadow-card">
              <h2 className="text-lg font-semibold">Policies</h2>
              <ul className="mt-4 space-y-2">{data.policies.map((p: any) => <li key={p.code} className="flex justify-between text-sm"><span>{p.title}</span><span className="text-xs text-muted-foreground">approved {fmtDate(p.approved)}</span></li>)}</ul>
            </section>
          )}
        </div>
        {grant.data && grant.data.nda_required && !grant.data.nda_ok && (
          <section className="rounded-xl border-2 p-6" style={{ borderColor: brand }}>
            <h2 className="text-lg font-semibold">Welcome, {grant.data.name}. Please accept the NDA</h2>
            <div className="mt-3 max-h-60 overflow-auto rounded-md border bg-muted/40 p-4"><Markdown>{grant.data.nda_text ?? ""}</Markdown></div>
            <div className="mt-4 flex flex-wrap items-end gap-2"><Field label="Type your full name to sign" className="min-w-64 flex-1"><Input value={signed} onChange={(e) => setSigned(e.target.value)} /></Field><Button disabled={!signed.trim()} onClick={acceptNda} style={{ background: brand }}>I agree</Button></div>
          </section>
        )}
        {access && <div className="flex items-center gap-2 rounded-lg border px-4 py-3 text-sm"><CheckCircle2 className="size-4 text-good-fg" /> Access granted to {grant.data.name} ({grant.data.company}) until {fmtDate(grant.data.expires_at)}.</div>}
        {grant.isError && <div className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm">{(grant.error as Error).message}</div>}
        {data.subprocessors?.length > 0 && (
          <section className="rounded-xl border bg-card p-6 shadow-card">
            <h2 className="text-lg font-semibold">Subprocessors</h2>
            <table className="mt-4 w-full text-sm"><thead><tr className="border-b text-left text-xs uppercase text-muted-foreground"><th className="py-2">Company</th><th>Purpose</th><th>Location</th></tr></thead>
              <tbody>{data.subprocessors.map((s: any) => <tr key={s.name} className="border-b last:border-0"><td className="py-2 font-medium">{s.name}</td><td>{s.purpose}</td><td>{s.location ?? "—"}</td></tr>)}</tbody></table>
          </section>
        )}
        {data.faqs?.length > 0 && (
          <section className="rounded-xl border bg-card p-6 shadow-card">
            <h2 className="text-lg font-semibold">Frequently asked questions</h2>
            <div className="mt-3 divide-y">{data.faqs.map((f: any, i: number) => (
              <div key={i}>
                <button className="flex w-full items-center justify-between py-3 text-left text-sm font-medium" onClick={() => setFaqOpen(faqOpen === i ? null : i)} aria-expanded={faqOpen === i}>{f.question}<ChevronDown className={cn("size-4 transition-transform", faqOpen === i && "rotate-180")} /></button>
                {faqOpen === i && <p className="pb-3 text-sm text-muted-foreground">{f.answer}</p>}
              </div>
            ))}</div>
          </section>
        )}
        {!access && (
          <section className="rounded-xl border bg-card p-6 shadow-card">
            <h2 className="text-lg font-semibold">Request access to security documents</h2>
            {sent ? <p className="mt-3 flex items-center gap-2 text-sm"><CheckCircle2 className="size-4 text-good-fg" /> Thanks. We'll review your request and send you a personal access link.</p> : (
              <form onSubmit={request} className="mt-4 grid gap-3 sm:grid-cols-3">
                <Field label="Name"><Input required value={req.name} onChange={(e) => setReq({ ...req, name: e.target.value })} /></Field>
                <Field label="Work email"><Input required type="email" value={req.email} onChange={(e) => setReq({ ...req, email: e.target.value })} /></Field>
                <Field label="Company"><Input required value={req.company} onChange={(e) => setReq({ ...req, company: e.target.value })} /></Field>
                <Field label="Why do you need access?" className="sm:col-span-3"><Textarea value={req.reason} onChange={(e) => setReq({ ...req, reason: e.target.value })} /></Field>
                <input type="text" name="website" tabIndex={-1} autoComplete="off" className="hidden" value={req.website} onChange={(e) => setReq({ ...req, website: e.target.value })} aria-hidden />
                {err && <p className="text-sm text-critical sm:col-span-3">{err}</p>}
                <div className="sm:col-span-3"><Button type="submit" style={{ background: brand }}>Request access</Button></div>
              </form>
            )}
          </section>
        )}
        {data.contact_email && <p className="flex items-center justify-center gap-2 text-sm text-muted-foreground"><Mail className="size-4" /> Security questions: <a className="underline" href={`mailto:${data.contact_email}`}>{data.contact_email}</a></p>}
        <p className="text-center text-xs text-muted-foreground">Powered by Keystone ISMS</p>
      </main>
    </div>
  );
}
