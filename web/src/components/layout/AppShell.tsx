import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { Command } from "cmdk";
import * as D from "@radix-ui/react-dialog";
import { ChevronsLeft, ChevronsRight, LogOut, Menu as MenuIcon, Monitor, Moon, Search, Sun, User } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { Menu } from "@/components/ui/dropdown";
import { NAV, BUILT } from "./nav";

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

function Sidebar({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const sections = useNav();
  return (
    <nav className="flex-1 space-y-4 overflow-y-auto px-2 py-3" aria-label="Main">
      {sections.map((s, i) => (
        <div key={i}>
          {s.label && !collapsed && <div className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/80">{s.label}</div>}
          <div className="space-y-0.5">
            {s.items.map((it) => (
              <NavLink
                key={it.to}
                to={it.to}
                end={it.to === "/"}
                onClick={onNavigate}
                title={collapsed ? it.label : undefined}
                className={({ isActive }) =>
                  cn("flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm transition-colors", isActive ? "bg-sidebar-active font-medium text-accent-foreground" : "text-sidebar-foreground hover:bg-muted", collapsed && "justify-center px-0")
                }
              >
                <it.icon className="size-4 shrink-0" />
                {!collapsed && <span className="truncate">{it.label}</span>}
              </NavLink>
            ))}
          </div>
        </div>
      ))}
    </nav>
  );
}

function CommandPalette({ open, setOpen }: { open: boolean; setOpen: (o: boolean) => void }) {
  const nav = useNavigate();
  const sections = useNav();
  return (
    <D.Root open={open} onOpenChange={setOpen}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/40" />
        <D.Content className="fixed left-1/2 top-[15vh] z-50 w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 overflow-hidden rounded-lg border bg-popover shadow-2xl">
          <D.Title className="sr-only">Go to</D.Title>
          <Command>
            <Command.Input autoFocus placeholder="Jump to a page…" className="w-full border-b bg-transparent px-4 py-3 text-sm outline-none" />
            <Command.List className="max-h-80 overflow-auto p-2">
              <Command.Empty className="py-6 text-center text-sm text-muted-foreground">No results</Command.Empty>
              {sections.map((s, i) => (
                <Command.Group key={i} heading={s.label ?? "Keystone"} className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-muted-foreground">
                  {s.items.map((it) => (
                    <Command.Item key={it.to} value={`${s.label ?? ""} ${it.label}`} onSelect={() => { nav(it.to); setOpen(false); }} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm data-[selected=true]:bg-muted">
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
          <button className="rounded p-1.5 hover:bg-muted md:hidden" onClick={() => setMobile(true)} aria-label="Open menu">
            <MenuIcon className="size-5" />
          </button>
          <button onClick={() => setPalette(true)} className="flex h-9 w-full max-w-sm items-center gap-2 rounded-md border bg-background px-3 text-sm text-muted-foreground hover:bg-muted">
            <Search className="size-4" />
            <span className="flex-1 text-left">Search or jump to…</span>
            <kbd className="hidden rounded border bg-muted px-1.5 text-[10px] font-medium sm:inline">⌘K</kbd>
          </button>
          <div className="ml-auto flex items-center gap-1">
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
                <button className="flex items-center gap-2 rounded-md py-1 pl-1 pr-2 hover:bg-muted" aria-label="Account menu">
                  <span className="grid size-7 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-foreground">{me?.display_name.split(" ").map((p) => p[0]).slice(0, 2).join("")}</span>
                  <span className="hidden text-left leading-tight sm:block">
                    <span className="block text-sm font-medium">{me?.display_name}</span>
                    <span className="block text-[11px] text-muted-foreground">{me?.role_label}</span>
                  </span>
                </button>
              }
              items={[
                { label: "My account", icon: User, onSelect: () => nav("/settings/account") },
                { label: "My employee portal", icon: User, onSelect: () => nav("/portal") },
                "sep",
                { label: "Sign out", icon: LogOut, onSelect: () => { logout().then(() => nav("/login"), () => nav("/login")); }, danger: true },
              ]}
            />
          </div>
        </header>
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8">{children}</div>
        </main>
      </div>
      <CommandPalette open={palette} setOpen={setPalette} />
    </div>
  );
}
