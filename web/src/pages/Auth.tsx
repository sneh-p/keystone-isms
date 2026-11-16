import { useState, type FormEvent, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/lib/auth";
import { safeRedirectPath } from "@/lib/safe-url";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";

function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <div className="grid min-h-full lg:grid-cols-2">
      <div className="relative hidden overflow-hidden bg-gradient-to-br from-indigo-600 via-indigo-700 to-violet-800 p-10 text-white lg:flex lg:flex-col lg:justify-between">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-lg bg-white/15 font-bold backdrop-blur">K</div>
          <span className="text-lg font-semibold">Keystone ISMS</span>
        </div>
        <div className="max-w-md">
          <ShieldCheck className="mb-6 size-10 opacity-90" />
          <h2 className="text-3xl font-semibold leading-tight">Run your security program in one place.</h2>
          <p className="mt-4 text-white/80">ISO 27001, SOC 2, NIST CSF and CIS controls, policies, risks, vendors, evidence and audits, with every change on an append-only audit trail.</p>
        </div>
        <p className="text-sm text-white/60">Self-hosted. Your data stays on your infrastructure.</p>
        <div className="pointer-events-none absolute -right-24 -top-24 size-96 rounded-full bg-white/10 blur-3xl" />
      </div>
      <div className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm animate-fade-in">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
          <div className="mt-6">{children}</div>
        </div>
      </div>
    </div>
  );
}

export function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await login(u, p);
      nav(safeRedirectPath((loc.state as any)?.from));
    } catch (x: any) {
      setErr(x.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <AuthLayout title="Sign in" subtitle="Welcome back to Keystone.">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Username">
          <Input autoFocus autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} />
        </Field>
        <Field label="Password">
          <Input type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} />
        </Field>
        {err && <p className="rounded-md bg-critical/10 px-3 py-2 text-sm text-critical" role="alert">{err}</p>}
        <Button type="submit" className="w-full" loading={busy}>Sign in</Button>
      </form>
    </AuthLayout>
  );
}

export function Setup() {
  const { bootstrap } = useAuth();
  const nav = useNavigate();
  const [f, setF] = useState({ username: "", display_name: "", email: "", password: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: any) => setF({ ...f, [k]: e.target.value });
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (f.password !== f.confirm) return toast.error("Passwords do not match.");
    setBusy(true);
    try {
      await bootstrap({ username: f.username, display_name: f.display_name, password: f.password, email: f.email || undefined });
      nav("/onboarding");
    } catch (x: any) {
      toast.error(x.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <AuthLayout title="Set up Keystone" subtitle="Create the first administrator account.">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Your name"><Input value={f.display_name} onChange={set("display_name")} /></Field>
        <Field label="Username"><Input value={f.username} onChange={set("username")} autoComplete="username" /></Field>
        <Field label="Email (optional)"><Input type="email" value={f.email} onChange={set("email")} /></Field>
        <Field label="Password" hint="12+ characters with three of: lowercase, uppercase, digit, symbol."><Input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></Field>
        <Field label="Confirm password"><Input type="password" value={f.confirm} onChange={set("confirm")} autoComplete="new-password" /></Field>
        <Button type="submit" className="w-full" loading={busy}>Create administrator</Button>
      </form>
    </AuthLayout>
  );
}

export function ChangePasswordGate() {
  const { refresh, logout } = useAuth();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (f.next !== f.confirm) return toast.error("Passwords do not match.");
    setBusy(true);
    try {
      await api("/auth/change-password", { body: { current: f.current, new: f.next } });
      toast.success("Password changed.");
      await refresh();
    } catch (x: any) {
      toast.error(x.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <AuthLayout title="Choose a new password" subtitle="Your administrator set a temporary password. Pick your own to continue.">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Current password"><Input type="password" value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} /></Field>
        <Field label="New password" hint="12+ characters with three of: lowercase, uppercase, digit, symbol."><Input type="password" value={f.next} onChange={(e) => setF({ ...f, next: e.target.value })} /></Field>
        <Field label="Confirm new password"><Input type="password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} /></Field>
        <Button type="submit" className="w-full" loading={busy}>Change password</Button>
        <Button type="button" variant="ghost" className="w-full" onClick={() => logout()}>Sign out</Button>
      </form>
    </AuthLayout>
  );
}
