import { useEffect, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { BookOpen, Check, CheckCircle2, ChevronLeft, Laptop, LogOut, ScrollText, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { api, downloadUrl, fragmentParam, setCsrf, upload } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { cn, fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Progress, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { Markdown } from "@/components/Markdown";

function PortalShell({ children }: { children: any }) {
  const { me, logout } = useAuth();
  const nav = useNavigate();
  return (
    <div className="min-h-full bg-muted/30">
      <header className="border-b bg-card">
        <div className="mx-auto flex h-14 max-w-4xl items-center gap-3 px-4">
          <div className="grid size-8 place-items-center rounded-lg bg-primary text-sm font-bold text-primary-foreground">K</div>
          <span className="font-semibold">Employee portal</span>
          <div className="ml-auto flex items-center gap-3 text-sm">
            {me?.permissions.includes("read") && <Link to="/" className="text-primary hover:underline">Back to Keystone</Link>}
            <span className="hidden text-muted-foreground sm:inline">{me?.display_name}</span>
            <Button size="sm" variant="ghost" onClick={() => logout().then(() => nav("/login"))}><LogOut /> Sign out</Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-4xl px-4 py-8">{children}</main>
    </div>
  );
}

export default function Portal() {
  const { me } = useAuth();
  const { data } = useApi<any>("/portal");
  const [read, setRead] = useState<any>(null);
  const [dev, setDev] = useState<any>(null);
  const ack = useAction((vid: number) => api(`/policies/versions/${vid}/acknowledge`, { method: "POST" }), { success: "Thanks, recorded.", invalidate: ["/portal"] });
  const attest = useAction(async () => {
    const fd = new FormData();
    fd.append("device_name", dev.device_name); fd.append("os", dev.os); fd.append("checks", JSON.stringify(dev.checks));
    if (dev.file) fd.append("file", dev.file);
    return upload("/portal/devices", fd);
  }, { success: "Device checklist saved.", invalidate: ["/portal"], onSuccess: () => setDev(null) });
  if (!data) return <PortalShell><Skeleton className="h-96" /></PortalShell>;
  const s = data.status;
  const total = s.policies_total + s.training_total + 1;
  const done = s.policies_done + s.training_done + (s.device_ok ? 1 : 0);
  return (
    <PortalShell>
      <h1 className="text-2xl font-semibold">Hi {me?.display_name.split(" ")[0]} 👋</h1>
      <p className="mt-1 text-muted-foreground">A few things keep you and the company secure. Here's what's left.</p>
      <Card className="mt-6"><CardBody>
        <div className="flex items-center justify-between text-sm"><span className="font-medium">Your progress</span><span className="tabular-nums text-muted-foreground">{done} of {total} done</span></div>
        <Progress className="mt-2" value={(100 * done) / total} tone={s.complete ? "good" : "primary"} />
        {s.complete && <p className="mt-3 flex items-center gap-2 text-sm text-[#0a7a0a] dark:text-good"><CheckCircle2 className="size-4" /> You're all set. Thank you!</p>}
      </CardBody></Card>

      <Card className="mt-6">
        <CardHeader title={<span className="flex items-center gap-2"><ScrollText className="size-4" /> Policies to accept</span>} description={`${s.policies_done} of ${s.policies_total} accepted`} />
        <CardBody className="space-y-2">
          {data.policies.length === 0 ? <p className="flex items-center gap-2 text-sm text-muted-foreground"><Check className="size-4 text-good" /> Nothing waiting.</p> : data.policies.map((v: any) => (
            <div key={v.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm">
              <span>{v.title} <span className="text-muted-foreground">v{v.version_label}</span></span>
              <Button size="sm" onClick={() => setRead(v)}>Read and accept</Button>
            </div>
          ))}
        </CardBody>
      </Card>

      <Card className="mt-6">
        <CardHeader title={<span className="flex items-center gap-2"><BookOpen className="size-4" /> Security training</span>} description={`${s.training_done} of ${s.training_total} completed this year`} />
        <CardBody className="grid gap-3 sm:grid-cols-2">
          {data.training.map((m: any) => (
            <Link key={m.key} to={`/portal/training/${m.key}`} className={cn("rounded-lg border p-4 transition-colors hover:bg-muted/50", m.completed_at && "border-good/30")}>
              <div className="flex items-start justify-between gap-2"><span className="font-medium">{m.title}</span>{m.completed_at ? <Badge tone="good"><Check className="size-3" /> Done</Badge> : <Badge tone="outline">{m.minutes} min</Badge>}</div>
              <p className="mt-1 text-xs text-muted-foreground">{m.summary}</p>
              {m.completed_at && <p className="mt-2 text-xs text-muted-foreground">Completed {fmtDate(m.completed_at)}</p>}
            </Link>
          ))}
        </CardBody>
      </Card>

      <Card className="mt-6">
        <CardHeader title={<span className="flex items-center gap-2"><Laptop className="size-4" /> Device security</span>} description="Confirm each work device meets the basics. Renew every 6 months."
          action={<Button size="sm" variant="outline" onClick={() => setDev({ device_name: "", os: "windows", checks: Object.fromEntries(Object.keys(data.device_checks).map((k) => [k, false])), file: null })}>Add device</Button>} />
        <CardBody className="space-y-2">
          {data.devices.length === 0 ? <p className="text-sm text-muted-foreground">No devices yet.</p> : data.devices.map((d: any) => (
            <button key={d.id} onClick={() => setDev({ device_name: d.device_name, os: d.os, checks: d.checks, file: null })} className="flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm hover:bg-muted/50">
              <span>{d.device_name} <span className="text-muted-foreground">· {d.os} · {fmtDate(d.attested_at)}</span></span>
              {d.compliant ? <Badge tone="good"><ShieldCheck className="size-3" /> Secure</Badge> : <Badge tone="warning">Needs attention</Badge>}
            </button>
          ))}
        </CardBody>
      </Card>

      <Dialog open={!!read} onOpenChange={(o) => !o && setRead(null)} wide title={read ? `${read.title} v${read.version_label}` : ""}
        footer={<Button onClick={() => { ack.mutate(read.id); setRead(null); }}><Check /> I have read and understood this policy</Button>}>
        {read?.body && <Markdown>{read.body}</Markdown>}
        {read?.attachment_id && <a href={downloadUrl(`/portal/policies/${read.id}/document`)} className="text-sm text-primary underline">Download document</a>}
      </Dialog>
      <Dialog open={!!dev} onOpenChange={(o) => !o && setDev(null)} title="Device security checklist" footer={<Button disabled={!dev?.device_name} loading={attest.isPending} onClick={() => attest.mutate(undefined)}>Save checklist</Button>}>
        {dev && <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Device name"><Input value={dev.device_name} onChange={(e) => setDev({ ...dev, device_name: e.target.value })} placeholder="e.g. Work laptop" /></Field>
            <Field label="Operating system"><Select value={dev.os} onChange={(v) => setDev({ ...dev, os: v })} options={[["windows", "Windows"], ["macos", "macOS"], ["linux", "Linux"], ["ios", "iOS"], ["android", "Android"], ["other", "Other"]].map(([value, label]) => ({ value, label }))} /></Field>
          </div>
          <div className="space-y-2">{Object.entries(data.device_checks).map(([k, label]: any) => (
            <label key={k} className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm"><input type="checkbox" checked={!!dev.checks[k]} onChange={(e) => setDev({ ...dev, checks: { ...dev.checks, [k]: e.target.checked } })} />{label}</label>
          ))}</div>
          <Field label="Screenshot (optional)"><input type="file" accept=".png,.jpg,.jpeg,.pdf" onChange={(e) => setDev({ ...dev, file: e.target.files?.[0] ?? null })} className="text-sm" /></Field>
        </div>}
      </Dialog>
    </PortalShell>
  );
}

export function TrainingModule() {
  const { key } = useParams();
  const nav = useNavigate();
  const { data } = useApi<any>(`/portal/training/${key}`);
  const [answers, setAnswers] = useState<number[]>([]);
  const [result, setResult] = useState<any>(null);
  const submit = useAction(() => api(`/portal/training/${key}`, { body: { answers } }), { invalidate: ["/portal"], onSuccess: (r: any) => { setResult(r); if (r.passed) toast.success("Passed. Well done!"); } });
  return (
    <PortalShell>
      <Link to="/portal" className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ChevronLeft className="size-4" /> Portal</Link>
      {!data ? <Skeleton className="h-96" /> : (
        <>
          <h1 className="text-2xl font-semibold">{data.title}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{data.minutes} minutes</p>
          <Card className="mt-6"><CardBody><Markdown>{data.body}</Markdown></CardBody></Card>
          <Card className="mt-6">
            <CardHeader title="Check your understanding" description={`Get ${data.pass_mark} of ${data.quiz.length} right to complete the module.`} />
            <CardBody className="space-y-5">
              {data.quiz.map((q: any, i: number) => (
                <fieldset key={i}>
                  <legend className="mb-2 text-sm font-medium">{i + 1}. {q.q}</legend>
                  <div className="space-y-1.5">{q.options.map((o: string, j: number) => (
                    <label key={j} className={cn("flex cursor-pointer items-center gap-3 rounded-md border px-3 py-2 text-sm", answers[i] === j && "border-primary bg-accent")}><input type="radio" name={`q${i}`} checked={answers[i] === j} onChange={() => { const a = [...answers]; a[i] = j; setAnswers(a); }} />{o}</label>
                  ))}</div>
                </fieldset>
              ))}
              {result && <p className={cn("rounded-md px-3 py-2 text-sm", result.passed ? "bg-good/10 text-[#0a7a0a] dark:text-good" : "bg-warning/10")}>{result.passed ? `Passed with ${result.score}/${result.out_of}.` : `${result.score}/${result.out_of}: not quite. Read the module again and retry.`}</p>}
              <div className="flex gap-2">
                <Button disabled={answers.filter((a) => a !== undefined).length !== data.quiz.length} loading={submit.isPending} onClick={() => submit.mutate(undefined)}>Submit answers</Button>
                {result?.passed && <Button variant="outline" onClick={() => nav("/portal")}>Back to portal</Button>}
              </div>
            </CardBody>
          </Card>
        </>
      )}
    </PortalShell>
  );
}

export function AcceptInvite() {
  const params = useParams();
  // SC-CRY-005: the token arrives after '#', never in a path or query the server logs; /invite/<token> still works.
  const [token] = useState(() => fragmentParam("token") ?? params.token ?? null);
  useEffect(() => { if (window.location.hash) window.history.replaceState(null, "", window.location.pathname); }, []);
  const tokenHeader = { "X-Invite-Token": token ?? "" };
  const { refresh } = useAuth();
  const nav = useNavigate();
  const info = useQuery<any>({ queryKey: ["/public/invite", token], queryFn: () => api("/public/invite", { headers: tokenHeader }), enabled: !!token });
  const [pw, setPw] = useState({ a: "", b: "" });
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (pw.a !== pw.b) return toast.error("Passwords do not match.");
    setBusy(true);
    try {
      const me = await api<any>("/public/invite", { body: { password: pw.a }, headers: tokenHeader });
      setCsrf(me.csrf_token);
      await refresh();
      nav("/portal");
    } catch (x: any) {
      toast.error(x.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid min-h-full place-items-center bg-muted/30 p-6">
      <Card className="w-full max-w-md"><CardBody className="p-6">
        <div className="mb-4 grid size-10 place-items-center rounded-lg bg-primary font-bold text-primary-foreground">K</div>
        {info.isError ? <p className="text-sm text-critical">{(info.error as Error).message}</p> : !info.data ? <Skeleton className="h-40" /> : (
          <form onSubmit={submit} className="space-y-4">
            <div><h1 className="text-xl font-semibold">Welcome, {info.data.full_name.split(" ")[0]}</h1><p className="mt-1 text-sm text-muted-foreground">Choose a password to open your employee portal. You'll sign in with {info.data.email}.</p></div>
            <Field label="Password" hint="12+ characters with three of: lowercase, uppercase, digit, symbol."><Input type="password" value={pw.a} onChange={(e) => setPw({ ...pw, a: e.target.value })} autoComplete="new-password" /></Field>
            <Field label="Confirm password"><Input type="password" value={pw.b} onChange={(e) => setPw({ ...pw, b: e.target.value })} autoComplete="new-password" /></Field>
            <Button type="submit" className="w-full" loading={busy}>Create my account</Button>
          </form>
        )}
      </CardBody></Card>
    </div>
  );
}
