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

/** Authenticated application routes. `nav` marks routes that appear in the sidebar. */
export const APP_ROUTES: { path: string; element: ReactNode; nav?: boolean }[] = [
  { path: "/", element: <Dashboard />, nav: true },
  { path: "/frameworks", element: <Frameworks />, nav: true },
  { path: "/frameworks/:code", element: <FrameworkDetail /> },
  { path: "/controls", element: <Controls />, nav: true },
  { path: "/soa", element: <Soa />, nav: true },
  { path: "/evidence", element: <Evidence />, nav: true },
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
