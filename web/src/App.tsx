import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router";
import { useAuth } from "@/lib/auth";
import { AppShell } from "@/components/layout/AppShell";
import { BUILT } from "@/components/layout/nav";
import { Skeleton } from "@/components/ui/misc";
import { ChangePasswordGate, Login, Setup } from "@/pages/Auth";

const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Frameworks = lazy(() => import("@/pages/Frameworks").then((m) => ({ default: m.Frameworks })));
const FrameworkDetail = lazy(() => import("@/pages/Frameworks").then((m) => ({ default: m.FrameworkDetail })));
const Controls = lazy(() => import("@/pages/Controls"));
const Soa = lazy(() => import("@/pages/Soa"));
const Evidence = lazy(() => import("@/pages/Evidence"));
const Risks = lazy(() => import("@/pages/Risks"));
const Tasks = lazy(() => import("@/pages/Tasks"));
const Onboarding = lazy(() => import("@/pages/Onboarding"));
const People = lazy(() => import("@/pages/People"));
const TrustCenterAdmin = lazy(() => import("@/pages/TrustCenter"));
const Integrations = lazy(() => import("@/pages/Integrations"));
const PublicTrust = lazy(() => import("@/pages/PublicTrust"));
const Portal = lazy(() => import("@/pages/Portal"));
const TrainingModule = lazy(() => import("@/pages/Portal").then((m) => ({ default: m.TrainingModule })));
const AcceptInvite = lazy(() => import("@/pages/Portal").then((m) => ({ default: m.AcceptInvite })));
const Assets = lazy(() => import("@/pages/Assets"));
const Vendors = lazy(() => import("@/pages/Vendors"));
const Questionnaires = lazy(() => import("@/pages/Questionnaires"));
const Assessments = lazy(() => import("@/pages/Assessments"));
const Exposure = lazy(() => import("@/pages/Exposure"));
const Policies = lazy(() => import("@/pages/Policies"));
const Incidents = lazy(() => import("@/pages/Incidents"));
const Nonconformities = lazy(() => import("@/pages/Improvement").then((m) => ({ default: m.Nonconformities })));
const Audits = lazy(() => import("@/pages/Improvement").then((m) => ({ default: m.Audits })));
const Reviews = lazy(() => import("@/pages/Improvement").then((m) => ({ default: m.Reviews })));
const Organisation = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Organisation })));
const Users = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Users })));
const AuditLog = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.AuditLog })));
const Account = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Account })));
const EmailSettings = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.EmailSettings })));
const SsoSettings = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.SsoSettings })));
const Reports = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Reports })));
const Channels = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Channels })));
const Provisioning = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Provisioning })));
const SystemHealth = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.SystemHealth })));
const AiSettings = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.AiSettings })));
const SecurityQuestionnaires = lazy(() => import("@/pages/SecurityQuestionnaires"));
const QuestionnaireDetail = lazy(() => import("@/pages/SecurityQuestionnaires").then((m) => ({ default: m.QuestionnaireDetail })));
const VendorPortal = lazy(() => import("@/pages/VendorPortal"));
const Workload = lazy(() => import("@/pages/Workload"));
const Privacy = lazy(() => import("@/pages/Privacy"));
const AccessReviews = lazy(() => import("@/pages/AccessReviews"));
const Continuity = lazy(() => import("@/pages/Continuity"));
const CalendarPage = lazy(() => import("@/pages/Calendar"));
const AttackSurface = lazy(() => import("@/pages/AttackSurface"));
const Configuration = lazy(() => import("@/pages/Configuration"));
const Help = lazy(() => import("@/pages/Help"));
const RegisterPage = lazy(() => import("@/pages/Registers"));
const SecurityReports = lazy(() => import("@/pages/Security").then((m) => ({ default: m.SecurityReports })));
const AccessCheck = lazy(() => import("@/pages/Security").then((m) => ({ default: m.AccessCheck })));
const Exceptions = lazy(() => import("@/pages/Security").then((m) => ({ default: m.Exceptions })));
const AlertInbox = lazy(() => import("@/pages/Measure").then((m) => ({ default: m.AlertInbox })));
const Indicators = lazy(() => import("@/pages/Measure").then((m) => ({ default: m.Indicators })));
const Maturity = lazy(() => import("@/pages/Measure").then((m) => ({ default: m.Maturity })));
const PhishingSimulations = lazy(() => import("@/pages/Outreach").then((m) => ({ default: m.PhishingSimulations })));
const PhishLanding = lazy(() => import("@/pages/Outreach").then((m) => ({ default: m.PhishLanding })));
const DomainProtection = lazy(() => import("@/pages/Outreach").then((m) => ({ default: m.DomainProtection })));
const VendorBreaches = lazy(() => import("@/pages/Outreach").then((m) => ({ default: m.VendorBreaches })));
const OnCall = lazy(() => import("@/pages/Outreach").then((m) => ({ default: m.OnCall })));
const PortalHelp = lazy(() => import("@/pages/Help").then((m) => ({ default: m.PortalHelp })));

/** Authenticated application routes. `nav` marks routes that appear in the sidebar. */
export const APP_ROUTES: { path: string; element: ReactNode; nav?: boolean }[] = [
  { path: "/", element: <Dashboard />, nav: true },
  { path: "/frameworks", element: <Frameworks />, nav: true },
  { path: "/frameworks/:code", element: <FrameworkDetail /> },
  { path: "/controls", element: <Controls />, nav: true },
  { path: "/soa", element: <Soa />, nav: true },
  { path: "/privacy", element: <Privacy />, nav: true },
  { path: "/access-reviews", element: <AccessReviews />, nav: true },
  { path: "/evidence", element: <Evidence />, nav: true },
  { path: "/risks", element: <Risks />, nav: true },
  { path: "/tasks", element: <Tasks />, nav: true },
  { path: "/onboarding", element: <Onboarding /> },
  { path: "/people", element: <People />, nav: true },
  { path: "/trust-center", element: <TrustCenterAdmin />, nav: true },
  { path: "/integrations", element: <Integrations />, nav: true },
  { path: "/security-questionnaires", element: <SecurityQuestionnaires />, nav: true },
  { path: "/security-questionnaires/:id", element: <QuestionnaireDetail /> },
  { path: "/assets", element: <Assets />, nav: true },
  { path: "/attack-surface", element: <AttackSurface />, nav: true },
  { path: "/configuration", element: <Configuration />, nav: true },
  { path: "/vendors", element: <Vendors />, nav: true },
  { path: "/questionnaires", element: <Questionnaires />, nav: true },
  { path: "/assessments", element: <Assessments />, nav: true },
  { path: "/exposure", element: <Exposure />, nav: true },
  { path: "/policies", element: <Policies />, nav: true },
  { path: "/incidents", element: <Incidents />, nav: true },
  { path: "/nonconformities", element: <Nonconformities />, nav: true },
  { path: "/audits", element: <Audits />, nav: true },
  { path: "/reviews", element: <Reviews />, nav: true },
  { path: "/reports", element: <Reports />, nav: true },
  { path: "/calendar", element: <CalendarPage />, nav: true },
  { path: "/workload", element: <Workload />, nav: true },
  { path: "/continuity", element: <Continuity />, nav: true },
  { path: "/settings/organisation", element: <Organisation />, nav: true },
  { path: "/settings/users", element: <Users />, nav: true },
  { path: "/settings/audit-log", element: <AuditLog />, nav: true },
  { path: "/settings/account", element: <Account />, nav: true },
  { path: "/settings/ai", element: <AiSettings />, nav: true },
  { path: "/settings/email", element: <EmailSettings />, nav: true },
  { path: "/settings/sso", element: <SsoSettings />, nav: true },
  { path: "/settings/provisioning", element: <Provisioning />, nav: true },
  { path: "/settings/channels", element: <Channels />, nav: true },
  { path: "/settings/system", element: <SystemHealth />, nav: true },
  { path: "/help", element: <Help /> },
  { path: "/registers/:key", element: <RegisterPage /> },
  { path: "/security-reports", element: <SecurityReports />, nav: true },
  { path: "/access-check", element: <AccessCheck />, nav: true },
  { path: "/exceptions", element: <Exceptions />, nav: true },
  { path: "/alerts", element: <AlertInbox />, nav: true },
  { path: "/indicators", element: <Indicators />, nav: true },
  { path: "/maturity", element: <Maturity />, nav: true },
  { path: "/phishing", element: <PhishingSimulations />, nav: true },
  { path: "/domain-protection", element: <DomainProtection />, nav: true },
  { path: "/vendor-breaches", element: <VendorBreaches />, nav: true },
  { path: "/on-call", element: <OnCall />, nav: true },
];
// Registers share one page; their sidebar entries and tabs exist in this build.
["obligations", "changes", "policy-exceptions", "screening", "confidentiality", "sites", "visitors", "physical-checks",
  "pentests", "findings", "applications", "threat-models", "release-signoffs", "crypto", "backups"].forEach((k) => BUILT.add(`/registers/${k}`));
APP_ROUTES.filter((r) => r.nav).forEach((r) => BUILT.add(r.path));

const Loading = () => (
  <div className="space-y-4">
    <Skeleton className="h-9 w-64" />
    <Skeleton className="h-72" />
  </div>
);

function Private({ children }: { children: ReactNode }) {
  const { me, loading, needsBootstrap } = useAuth();
  const loc = useLocation();
  if (loading) return <div className="grid h-full place-items-center text-sm text-muted-foreground">Loading…</div>;
  if (needsBootstrap) return <Navigate to="/setup" replace />;
  if (!me) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if (me.must_change_password) return <ChangePasswordGate />;
  return <>{children}</>;
}

/** Staff-only area: employees are sent to their portal. */
function Staff({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  if (me && !me.permissions.includes("read")) return <Navigate to="/portal" replace />;
  return <>{children}</>;
}

export default function App() {
  const { me, needsBootstrap } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={me ? <Navigate to="/" replace /> : needsBootstrap ? <Navigate to="/setup" replace /> : <Login />} />
      <Route path="/setup" element={needsBootstrap ? <Setup /> : <Navigate to="/" replace />} />
      <Route path="/trust/:slug" element={<Suspense fallback={<Loading />}><PublicTrust /></Suspense>} />
      <Route path="/vendor-portal" element={<Suspense fallback={<Loading />}><VendorPortal /></Suspense>} />
      <Route path="/phish" element={<Suspense fallback={<Loading />}><PhishLanding /></Suspense>} />
      <Route path="/invite" element={<Suspense fallback={<Loading />}><AcceptInvite /></Suspense>} />
      <Route path="/invite/:token" element={<Suspense fallback={<Loading />}><AcceptInvite /></Suspense>} />
      <Route path="/portal" element={<Private><Suspense fallback={<Loading />}><Portal /></Suspense></Private>} />
      <Route path="/portal/help" element={<Private><Suspense fallback={<Loading />}><PortalHelp /></Suspense></Private>} />
      <Route path="/portal/training/:key" element={<Private><Suspense fallback={<Loading />}><TrainingModule /></Suspense></Private>} />
      <Route
        path="/*"
        element={
          <Private>
            <Staff>
            <AppShell>
              <Suspense fallback={<Loading />}>
                <Routes>
                  {APP_ROUTES.map((r) => <Route key={r.path} path={r.path} element={r.element} />)}
                  <Route path="*" element={<div className="py-20 text-center text-muted-foreground">Page not found.</div>} />
                </Routes>
              </Suspense>
            </AppShell>
            </Staff>
          </Private>
        }
      />
    </Routes>
  );
}
