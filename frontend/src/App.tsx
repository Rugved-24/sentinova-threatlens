import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./context/AuthContext";
import { AppShell } from "./layout/AppShell";
import { Login } from "./pages/Login";
import type { Role } from "./lib/types";
import { can } from "./lib/utils";

const Analyst = lazy(() => import("./pages/Analyst").then((module) => ({ default: module.Analyst })));
const Audit = lazy(() => import("./pages/Audit").then((module) => ({ default: module.Audit })));
const Executive = lazy(() => import("./pages/Executive").then((module) => ({ default: module.Executive })));
const Feeds = lazy(() => import("./pages/Feeds").then((module) => ({ default: module.Feeds })));
const Hunting = lazy(() => import("./pages/Hunting").then((module) => ({ default: module.Hunting })));
const Incidents = lazy(() => import("./pages/Incidents").then((module) => ({ default: module.Incidents })));
const Reports = lazy(() => import("./pages/Reports").then((module) => ({ default: module.Reports })));
const Settings = lazy(() => import("./pages/Settings").then((module) => ({ default: module.Settings })));
const Users = lazy(() => import("./pages/Users").then((module) => ({ default: module.Users })));

function FullScreenLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-ink-950">
      <div className="flex flex-col items-center gap-4">
        <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-400/25 bg-cyan-400/10">
          <span className="absolute inset-0 animate-ping rounded-2xl border border-cyan-400/20" />
          <span className="h-5 w-5 rounded-full border-2 border-cyan-300 border-t-transparent animate-spin" />
        </div>
        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Initialising intelligence fabric</p>
      </div>
    </div>
  );
}

function Protected({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <FullScreenLoader />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function Guard({ permission, children }: { permission: string; children: React.ReactNode }) {
  const { user } = useAuth();
  if (!can(user?.role as Role | undefined, permission)) return <Navigate to="/" replace />;
  return <>{children}</>;
}

export default function App() {
  const { user, loading } = useAuth();

  return (
    <Suspense fallback={<FullScreenLoader />}>
      <Routes>
        <Route path="/login" element={loading ? <FullScreenLoader /> : user ? <Navigate to="/" replace /> : <Login />} />
      <Route
        element={
          <Protected>
            <AppShell />
          </Protected>
        }
      >
        <Route index element={<Executive />} />
        <Route
          path="analyst"
          element={
            <Guard permission="manage_alerts">
              <Analyst />
            </Guard>
          }
        />
        <Route
          path="incidents"
          element={
            <Guard permission="read_incidents">
              <Incidents />
            </Guard>
          }
        />
        <Route
          path="hunting"
          element={
            <Guard permission="search">
              <Hunting />
            </Guard>
          }
        />
        <Route
          path="reports"
          element={
            <Guard permission="generate_reports">
              <Reports />
            </Guard>
          }
        />
        <Route
          path="feeds"
          element={
            <Guard permission="configure_feeds">
              <Feeds />
            </Guard>
          }
        />
        <Route
          path="audit"
          element={
            <Guard permission="view_audit">
              <Audit />
            </Guard>
          }
        />
        <Route
          path="users"
          element={
            <Guard permission="manage_users">
              <Users />
            </Guard>
          }
        />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
