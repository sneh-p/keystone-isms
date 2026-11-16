import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
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
const Reports = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Reports })));

/** Authenticated application routes. `nav` marks routes that appear in the sidebar. */
export const APP_ROUTES: { path: string; element: ReactNode; nav?: boolean }[] = [
  { path: "/", element: <Dashboard />, nav: true },
  { path: "/frameworks", element: <Frameworks />, nav: true },
  { path: "/frameworks/:code", element: <FrameworkDetail /> },
  { path: "/controls", element: <Controls />, nav: true },
  { path: "/soa", element: <Soa />, nav: true },
  { path: "/evidence", element: <Evidence />, nav: true },
  { path: "/risks", element: <Risks />, nav: true },
  { path: "/assets", element: <Assets />, nav: true },
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
  { path: "/settings/organisation", element: <Organisation />, nav: true },
  { path: "/settings/users", element: <Users />, nav: true },
  { path: "/settings/audit-log", element: <AuditLog />, nav: true },
  { path: "/settings/account", element: <Account />, nav: true },
];
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

export default function App() {
  const { me, needsBootstrap } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={me ? <Navigate to="/" replace /> : needsBootstrap ? <Navigate to="/setup" replace /> : <Login />} />
      <Route path="/setup" element={needsBootstrap ? <Setup /> : <Navigate to="/" replace />} />
      <Route
        path="/*"
        element={
          <Private>
            <AppShell>
              <Suspense fallback={<Loading />}>
                <Routes>
                  {APP_ROUTES.map((r) => <Route key={r.path} path={r.path} element={r.element} />)}
                  <Route path="*" element={<div className="py-20 text-center text-muted-foreground">Page not found.</div>} />
                </Routes>
              </Suspense>
            </AppShell>
          </Private>
        }
      />
    </Routes>
  );
}
