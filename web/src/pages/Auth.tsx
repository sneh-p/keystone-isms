import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/lib/auth";
import { safeRedirectPath } from "@/lib/safe-url";
import { api, fragmentParam } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { BrandMark } from "@/components/ui/brand";

function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <div className="grid min-h-full lg:grid-cols-2">
      <aside aria-label="About Keystone" className="bg-blueprint relative hidden overflow-hidden bg-brand p-10 text-brand-foreground lg:flex lg:flex-col lg:justify-between">
        <div className="flex items-center gap-3">
          <BrandMark tone="light" className="size-9" />
          <span className="text-lg font-semibold tracking-tight">Keystone ISMS</span>
        </div>
        {/* A large arch with its keystone lit, drawn behind the copy. */}
        <svg viewBox="0 0 400 300" className="pointer-events-none absolute -bottom-10 -right-28 w-[30rem] opacity-[0.09]" aria-hidden focusable="false">
          <path d="M60 300V170a140 140 0 0 1 280 0v130" fill="none" stroke="white" strokeWidth="34" />
          <path d="M176 8h48l-9 62h-30z" fill="white" />
        </svg>
        <div className="relative max-w-md">
          <ShieldCheck className="mb-6 size-9 text-sidebar-indicator" aria-hidden />
          <h2 className="text-[2rem] font-semibold leading-tight tracking-[-0.02em]">Run your security program in one place.</h2>
          <p className="mt-4 leading-relaxed text-white/75">ISO 27001, SOC 2, NIST CSF and CIS controls, policies, risks, vendors, evidence and audits, with every change on an append-only audit trail.</p>
        </div>
        <p className="relative text-sm text-white/60">Self-hosted. Your data stays on your infrastructure.</p>
      </aside>
      <main className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm animate-fade-in">
          <BrandMark className="mb-8 size-10 lg:hidden" />
          <h1 className="text-[1.75rem] font-semibold tracking-[-0.02em]">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
          <div className="mt-6">{children}</div>
        </div>
      </main>
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
      void nav(safeRedirectPath((loc.state as any)?.from));
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
        {err && <p className="rounded-md bg-critical/10 px-3 py-2 text-sm text-critical-fg" role="alert">{err}</p>}
        <Button type="submit" className="w-full" loading={busy}>Sign in</Button>
      </form>
      <SsoButtons />
    </AuthLayout>
  );
}

const SSO_LABEL: Record<string, string> = { entra: "Microsoft", google: "Google", okta: "Okta" };
const SSO_ERROR: Record<string, string> = {
  no_account: "There is no Keystone account for that sign-in. Ask an administrator to add you.",
  wrong_tenant: "That account belongs to a different organisation.",
  invalid_token: "The sign-in couldn't be verified. Please try again.",
  invalid_request: "The sign-in expired or was started in another browser. Please try again.",
  provider_error: "The sign-in was cancelled or the provider returned an error.",
  not_configured: "This sign-in option isn't available.",
};

/** "Sign in with Microsoft / Google": a top-level navigation to the API, which redirects to the provider. */
function SsoButtons() {
  const [status, setStatus] = useState<string[]>([]);
  const [error] = useState(() => fragmentParam("sso_error"));
  useEffect(() => {
    api<{ sso: string[] }>("/auth/status").then((r) => setStatus(r.sso ?? []), () => setStatus([]));
    if (fragmentParam("sso_error")) window.history.replaceState(null, "", window.location.pathname);
  }, []);
  return (
    <>
      {error && <p className="mt-4 rounded-md bg-critical/10 px-3 py-2 text-sm text-critical-fg" role="alert">{SSO_ERROR[error] ?? SSO_ERROR.invalid_request}</p>}
      {status.length > 0 && (
        <div className="mt-6 space-y-2">
          <div className="flex items-center gap-3 text-xs text-muted-foreground"><span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" /></div>
          {status.map((k) => (
            <a key={k} href={`/api/auth/oidc/${k}/start`} className="flex h-10 w-full items-center justify-center gap-2 rounded-md border bg-card text-sm font-medium shadow-card hover:bg-muted">
              Sign in with {SSO_LABEL[k] ?? k}
            </a>
          ))}
        </div>
      )}
    </>
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
      void nav("/onboarding");
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
