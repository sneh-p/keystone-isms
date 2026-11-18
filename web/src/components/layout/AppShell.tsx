import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router";
import { Command } from "cmdk";
import * as D from "@radix-ui/react-dialog";
import { ChevronDown, ChevronsLeft, ChevronsRight, CircleHelp, Compass, FileSearch, LifeBuoy, LogOut, Menu as MenuIcon, Monitor, Moon, Search, Sun, User } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { helpAnchorFor } from "@/lib/help";
import { Menu } from "@/components/ui/dropdown";
import { NotificationBell } from "@/components/NotificationBell";
import { Tour, useTourState } from "@/components/Tour";
import { AREAS, BUILT, NAV, PAGES, type NavItem } from "./nav";
import { appTourSteps, sectionTourName } from "./tour-steps";

function Logo({ collapsed }: { collapsed?: boolean }) {
  return (
    <div className="flex items-center gap-2.5 px-3">
      <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-primary text-sm font-bold text-primary-foreground shadow-sm">K</div>
      {!collapsed && (
        <div className="leading-tight">
          <div className="text-sm font-semibold">Keystone</div>
          <div className="text-[11px] text-muted-foreground">ISMS</div>
        </div>
      )}
    </div>
  );
}

function useNav() {
  const { can } = useAuth();
  return NAV.map((s) => ({ ...s, items: s.items.filter((i) => (!i.perm || can(i.perm)) && (BUILT.size === 0 || BUILT.has(i.to))) })).filter((s) => s.items.length);
}

const GROUPS_KEY = "ks-nav-groups";

function readClosedGroups(): string[] {
  try { return JSON.parse(localStorage.getItem(GROUPS_KEY) ?? "[]"); } catch { return []; }
}

function isActive(it: NavItem, path: string): boolean {
  if (it.to === "/") return path === "/";
  return [it.to, ...(it.also ?? [])].some((p) => path === p || path.startsWith(p + "/"));
}

function Sidebar({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const sections = useNav();
  const { pathname } = useLocation();
  const [closed, setClosed] = useState<string[]>(readClosedGroups);
  const toggle = (label: string) => setClosed((c) => {
    const next = c.includes(label) ? c.filter((x) => x !== label) : [...c, label];
    try { localStorage.setItem(GROUPS_KEY, JSON.stringify(next)); } catch { /* storage unavailable: keep in memory */ }
    return next;
  });
  return (
    <nav className="flex-1 space-y-3 overflow-y-auto px-2 py-3" aria-label="Main">
      {sections.map((s, i) => {
        const hasActive = s.items.some((it) => isActive(it, pathname));
        const open = collapsed || !s.label || hasActive || !closed.includes(s.label);
        const listId = `nav-group-${i}`;
        return (
          <div key={i} data-tour={sectionTourName(s.label, s.items[0].label)}>
            {s.label && !collapsed && (
              <button type="button" onClick={() => toggle(s.label!)} aria-expanded={open} aria-controls={listId} disabled={hasActive}
                className="mb-1 flex w-full items-center justify-between rounded px-3 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground disabled:cursor-default disabled:hover:text-muted-foreground">
                {s.label}
                {!hasActive && <ChevronDown className={cn("size-3.5 transition-transform", !open && "-rotate-90")} aria-hidden />}
              </button>
            )}
            {open && (
              <div id={listId} className="space-y-0.5">
                {s.items.map((it) => {
                  const active = isActive(it, pathname);
                  return (
                    <NavLink key={it.to} to={it.to} onClick={onNavigate} title={collapsed ? it.label : undefined} aria-current={active ? "page" : undefined}
                      className={cn("flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm transition-colors", active ? "bg-sidebar-active font-medium text-accent-foreground" : "text-sidebar-foreground hover:bg-muted", collapsed && "justify-center px-0")}>
                      <it.icon className="size-4 shrink-0" />
                      {!collapsed && <span className="truncate">{it.label}</span>}
                    </NavLink>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </nav>
  );
}

/** Tab bar for screens that share one sidebar entry (Vendors, Improvement, Settings). */
function AreaTabs() {
  const { pathname } = useLocation();
  const { can } = useAuth();
  const area = AREAS.find((a) => a.tabs.some((t) => pathname === t.to || pathname.startsWith(t.to + "/")));
  if (!area) return null;
  const tabs = area.tabs.filter((t) => !t.perm || can(t.perm));
  if (tabs.length < 2) return null;
  return (
    <nav aria-label={`${area.name} sections`} className="-mt-2 mb-5 flex gap-1 overflow-x-auto border-b">
      {tabs.map((t) => (
        <NavLink key={t.to} to={t.to} className={({ isActive }) => cn("-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors", isActive ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
          {t.label}
        </NavLink>
      ))}
    </nav>
  );
}

type Hit = { kind: string; label: string; ref: string; title: string; page: string };

/** The palette's record results: searched on the server once the query has 2+ characters, 200 ms after typing stops. */
function useRecordSearch(query: string, enabled: boolean) {
  const [debounced, setDebounced] = useState(query);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 200);
    return () => clearTimeout(t);
  }, [query]);
  return useQuery<Hit[]>({ queryKey: ["/search", debounced], queryFn: () => api<Hit[]>(`/search?q=${encodeURIComponent(debounced)}`), enabled: enabled && debounced.length >= 2, staleTime: 30_000 });
}

function CommandPalette({ open, setOpen }: { open: boolean; setOpen: (o: boolean) => void }) {
  const nav = useNavigate();
  const { can } = useAuth();
  const [query, setQuery] = useState("");
  const records = useRecordSearch(query, open && can("read"));
  const pages = PAGES.filter((p) => (!p.perm || can(p.perm)) && (BUILT.size === 0 || BUILT.has(p.to)));
  const groups = [...new Set(pages.map((p) => p.section))];
  const go = (to: string) => { void nav(to); setOpen(false); setQuery(""); };
  return (
    <D.Root open={open} onOpenChange={setOpen}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/40" />
        <D.Content className="fixed left-1/2 top-[15vh] z-50 w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 overflow-hidden rounded-lg border bg-popover shadow-2xl">
          <D.Title className="sr-only">Go to</D.Title>
          <Command>
            <Command.Input autoFocus value={query} onValueChange={setQuery} placeholder="Jump to a page or find a record…" className="w-full border-b bg-transparent px-4 py-3 text-sm outline-none" />
            <Command.List className="max-h-96 overflow-auto p-2">
              <Command.Empty className="py-6 text-center text-sm text-muted-foreground">{records.isFetching ? "Searching…" : "No results"}</Command.Empty>
              {(records.data ?? []).length > 0 && (
                <Command.Group heading="Records" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-muted-foreground">
                  {records.data!.map((h) => (
                    <Command.Item key={`${h.kind}-${h.page}`} value={`${query} ${h.ref} ${h.title} ${h.page}`} onSelect={() => go(h.page)} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm data-[selected=true]:bg-muted">
                      <FileSearch className="size-4 shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1 truncate"><span className="font-mono text-xs text-muted-foreground">{h.ref}</span> {h.title}</span>
                      <span className="shrink-0 text-xs text-muted-foreground">{h.label}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              <Command.Group heading="Help" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-muted-foreground">
                <Command.Item value="help user guide how to" onSelect={() => go("/help")} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm data-[selected=true]:bg-muted">
                  <LifeBuoy className="size-4 text-muted-foreground" />
                  Help and user guide
                </Command.Item>
              </Command.Group>
              {groups.map((g) => (
                <Command.Group key={g} heading={g} className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-muted-foreground">
                  {pages.filter((p) => p.section === g).map((it) => (
                    <Command.Item key={it.to} value={`${g} ${it.label}`} onSelect={() => go(it.to)} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm data-[selected=true]:bg-muted">
                      <it.icon className="size-4 text-muted-foreground" />
                      {it.label}
                    </Command.Item>
                  ))}
                </Command.Group>
              ))}
            </Command.List>
          </Command>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { me, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("ks-nav") === "1");
  const [mobile, setMobile] = useState(false);
  const [palette, setPalette] = useState(false);
  const nav = useNavigate();
  const loc = useLocation();
  const sections = useNav();
  const tourState = useTourState("app");
  const [tour, setTour] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  // First visit: the tour starts by itself once, except in the setup wizard (it would cover the wizard).
  const autoTour = tourState.loaded && !tourState.seen && !dismissed && loc.pathname !== "/onboarding";
  const tourOpen = tour || autoTour;
  const phone = useMemo(() => tourOpen && window.matchMedia("(max-width: 767px)").matches, [tourOpen]);
  useEffect(() => {
    if (tourOpen) { setMobile(false); setPalette(false); }
  }, [tourOpen]);
  const endTour = (completed: boolean) => {
    setTour(false);
    setDismissed(true);
    if (!tourState.seen || completed) tourState.record(completed ? "completed" : "skipped");
  };
  useEffect(() => setMobile(false), [loc.pathname]);
  useEffect(() => {
    const fn = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
    };
    window.addEventListener("keydown", fn);
    return () => window.removeEventListener("keydown", fn);
  }, []);
  const toggle = () => {
    setCollapsed((c) => {
      try { localStorage.setItem("ks-nav", c ? "0" : "1"); } catch { /* ignore */ }
      return !c;
    });
  };
  const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;
  return (
    <div className="flex h-full">
      <a href="#main" className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground focus:not-sr-only focus:fixed focus:left-3 focus:top-3">Skip to content</a>
      <aside className={cn("hidden shrink-0 flex-col border-r bg-sidebar transition-[width] md:flex", collapsed ? "w-16" : "w-64")}>
        <div className="flex h-14 items-center border-b">
          <Logo collapsed={collapsed} />
        </div>
        <Sidebar collapsed={collapsed} />
        <button onClick={toggle} className="flex items-center gap-2 border-t px-5 py-3 text-xs text-muted-foreground hover:text-foreground" aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
          {collapsed ? <ChevronsRight className="size-4" /> : <><ChevronsLeft className="size-4" /> Collapse</>}
        </button>
      </aside>
      {mobile && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setMobile(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-72 flex-col border-r bg-sidebar">
            <div className="flex h-14 items-center border-b"><Logo /></div>
            <Sidebar collapsed={false} onNavigate={() => setMobile(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b bg-card/80 px-4 backdrop-blur">
          <button data-tour="menu" className="rounded p-1.5 hover:bg-muted md:hidden" onClick={() => setMobile(true)} aria-label="Open menu">
            <MenuIcon className="size-5" />
          </button>
          <button data-tour="search" onClick={() => setPalette(true)} className="flex h-9 w-full min-w-0 max-w-sm items-center gap-2 rounded-md border bg-background px-3 text-sm text-muted-foreground hover:bg-muted">
            <Search className="size-4 shrink-0" />
            <span className="min-w-0 flex-1 truncate text-left">Search or jump to…</span>
            <kbd className="hidden rounded border bg-muted px-1.5 text-[10px] font-medium sm:inline">⌘K</kbd>
          </button>
          <div className="ml-auto flex items-center gap-1">
            <Link data-tour="help" to={`/help#${helpAnchorFor(loc.pathname)}`} aria-label="Help for this page" title="Help for this page" className="rounded-md p-2 hover:bg-muted">
              <CircleHelp className="size-4" />
            </Link>
            <span data-tour="notifications" className="inline-flex"><NotificationBell /></span>
            <Menu
              trigger={<button className="rounded-md p-2 hover:bg-muted" aria-label="Theme"><ThemeIcon className="size-4" /></button>}
              items={[
                { label: "Light", icon: Sun, onSelect: () => setTheme("light") },
                { label: "Dark", icon: Moon, onSelect: () => setTheme("dark") },
                { label: "System", icon: Monitor, onSelect: () => setTheme("system") },
              ]}
            />
            <Menu
              trigger={
                <button data-tour="account" className="flex items-center gap-2 rounded-md py-1 pl-1 pr-2 hover:bg-muted">
                  <span className="grid size-7 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-foreground">{me?.display_name.split(" ").map((p) => p[0]).slice(0, 2).join("")}</span>
                  <span className="hidden text-left leading-tight sm:block">
                    <span className="block text-sm font-medium">{me?.display_name}</span>
                    <span className="block text-[11px] text-muted-foreground">{me?.role_label}</span>
                  </span>
                </button>
              }
              items={[
                { label: "My account", icon: User, onSelect: () => { void nav("/settings/account"); } },
                { label: "My employee portal", icon: User, onSelect: () => { void nav("/portal"); } },
                { label: "Help", icon: LifeBuoy, onSelect: () => { void nav("/help"); } },
                { label: "Take the tour", icon: Compass, onSelect: () => setTour(true) },
                "sep",
                { label: "Sign out", icon: LogOut, onSelect: () => { logout().then(() => nav("/login"), () => nav("/login")); }, danger: true },
              ]}
            />
          </div>
        </header>
        <main id="main" tabIndex={-1} className="flex-1 overflow-y-auto focus:outline-none">
          <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8"><AreaTabs />{children}</div>
        </main>
      </div>
      <CommandPalette open={palette} setOpen={setPalette} />
      {tourOpen && <Tour label="Keystone tour" steps={appTourSteps(me?.display_name.split(" ")[0] ?? "", sections.map((x) => sectionTourName(x.label, x.items[0].label)), phone)} onEnd={endTour} />}
    </div>
  );
}
