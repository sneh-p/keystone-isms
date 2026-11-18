import {
  Activity, AlertOctagon, BadgeAlert, Building, FileWarning, GitPullRequestArrow, IdCard, Scale, UserX, CalendarDays, Crosshair, UsersRound, BookOpen, Boxes, Building2, ClipboardList, FileCheck2, Gauge, Globe2, Fingerprint, Handshake, HeartPulse, KeyRound, LifeBuoy,
  LayoutDashboard, ListChecks, Mail, Map as MapIcon, MessageSquareText, Paperclip, Plug, ScrollText, ServerCog, Settings, ShieldCheck, Siren, Sparkles, UserCheck, UserCog, Users, Wrench,
} from "lucide-react";

export type NavItem = { label: string; to: string; icon: any; perm?: string; also?: string[] };
export type NavSection = { label?: string; items: NavItem[] };
export type AreaTab = { label: string; to: string; perm?: string };

/** Screens that belong together share one sidebar entry and a tab bar (rendered by the app shell). */
export const AREAS: { name: string; tabs: AreaTab[] }[] = [
  { name: "Vendors", tabs: [
    { label: "Vendors", to: "/vendors" },
    { label: "Vendor questionnaires", to: "/questionnaires" },
    { label: "Vendor assessments", to: "/assessments" },
  ] },
  { name: "Improvement", tabs: [
    { label: "Nonconformities", to: "/nonconformities" },
    { label: "Audits", to: "/audits" },
    { label: "Management review", to: "/reviews" },
  ] },
  { name: "Exceptions", tabs: [
    { label: "All exceptions", to: "/exceptions" },
    { label: "Policy exceptions", to: "/registers/policy-exceptions" },
  ] },
  { name: "People security", tabs: [
    { label: "Background checks", to: "/registers/screening", perm: "people.write" },
    { label: "Confidentiality agreements", to: "/registers/confidentiality", perm: "people.write" },
  ] },
  { name: "Physical security", tabs: [
    { label: "Sites and secure areas", to: "/registers/sites" },
    { label: "Physical security checks", to: "/registers/physical-checks" },
    { label: "Visitor log", to: "/registers/visitors", perm: "asset.write" },
  ] },
  { name: "Settings", tabs: [
    { label: "Organisation", to: "/settings/organisation" },
    { label: "Users", to: "/settings/users", perm: "users.manage" },
    { label: "Audit log", to: "/settings/audit-log", perm: "audit_log.view" },
    { label: "AI", to: "/settings/ai", perm: "ai.manage" },
    { label: "Email", to: "/settings/email", perm: "users.manage" },
    { label: "Chat and webhooks", to: "/settings/channels", perm: "integration.manage" },
    { label: "Single sign-on", to: "/settings/sso", perm: "users.manage" },
    { label: "Provisioning", to: "/settings/provisioning", perm: "users.manage" },
    { label: "System health", to: "/settings/system", perm: "users.manage" },
    { label: "My account", to: "/settings/account" },
  ] },
];

const areaPaths = (name: string) => AREAS.find((a) => a.name === name)!.tabs.map((t) => t.to);

export const NAV: NavSection[] = [
  { items: [{ label: "Overview", to: "/", icon: LayoutDashboard }] },
  {
    label: "Compliance",
    items: [
      { label: "Frameworks", to: "/frameworks", icon: BookOpen },
      { label: "Controls", to: "/controls", icon: ShieldCheck },
      { label: "Tasks", to: "/tasks", icon: ListChecks },
      { label: "Calendar", to: "/calendar", icon: CalendarDays },
      { label: "Policies", to: "/policies", icon: ScrollText },
      { label: "Evidence", to: "/evidence", icon: Paperclip },
      { label: "Statement of Applicability", to: "/soa", icon: FileCheck2 },
      { label: "Privacy", to: "/privacy", icon: Fingerprint },
      { label: "Obligations", to: "/registers/obligations", icon: Scale },
      { label: "Exceptions", to: "/exceptions", icon: FileWarning, also: areaPaths("Exceptions") },
    ],
  },
  {
    label: "Risk",
    items: [
      { label: "Risk register", to: "/risks", icon: Gauge },
      { label: "Assets", to: "/assets", icon: Boxes },
      { label: "Attack surface", to: "/attack-surface", icon: Crosshair },
      { label: "Configuration", to: "/configuration", icon: ServerCog },
      { label: "Changes", to: "/registers/changes", icon: GitPullRequestArrow },
    ],
  },
  {
    label: "Third parties",
    items: [
      { label: "Vendors", to: "/vendors", icon: Handshake, also: areaPaths("Vendors") },
      { label: "Entra exposure", to: "/exposure", icon: MapIcon },
    ],
  },
  {
    label: "Trust and people",
    items: [
      { label: "People", to: "/people", icon: Users },
      { label: "People security", to: "/registers/screening", icon: IdCard, perm: "people.write", also: areaPaths("People security") },
      { label: "Access reviews", to: "/access-reviews", icon: UserCheck },
      { label: "Leaver access check", to: "/access-check", icon: UserX, perm: "access_review.manage" },
      { label: "Trust Center", to: "/trust-center", icon: Globe2 },
      { label: "Customer questionnaires", to: "/security-questionnaires", icon: MessageSquareText },
      { label: "Integrations", to: "/integrations", icon: Plug },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Security reports", to: "/security-reports", icon: BadgeAlert, perm: "incident.write" },
      { label: "Incidents", to: "/incidents", icon: Siren },
      { label: "Business continuity", to: "/continuity", icon: LifeBuoy },
      { label: "Physical security", to: "/registers/sites", icon: Building, also: areaPaths("Physical security") },
      { label: "Improvement", to: "/nonconformities", icon: Wrench, also: areaPaths("Improvement") },
      { label: "Workload", to: "/workload", icon: UsersRound },
      { label: "Reports", to: "/reports", icon: Activity },
    ],
  },
  { items: [{ label: "Settings", to: "/settings/organisation", icon: Settings, also: areaPaths("Settings") }] },
];

/** Every screen, for the command palette: sidebar entries plus the tabs inside areas. */
export const PAGES: { section: string; label: string; to: string; icon: any; perm?: string }[] = (() => {
  const icons: Record<string, any> = { "/questionnaires": ClipboardList, "/assessments": Handshake, "/audits": Wrench, "/reviews": Wrench,
    "/settings/users": UserCog, "/settings/audit-log": AlertOctagon, "/settings/ai": Sparkles, "/settings/email": Mail, "/settings/sso": KeyRound, "/settings/system": HeartPulse, "/settings/provisioning": UserCog, "/settings/channels": Mail, "/settings/account": KeyRound, "/settings/organisation": Building2 };
  const out: { section: string; label: string; to: string; icon: any; perm?: string }[] = [];
  for (const s of NAV) for (const it of s.items) {
    const area = AREAS.find((a) => a.tabs.some((t) => t.to === it.to));
    if (area) for (const t of area.tabs) out.push({ section: area.name, label: t.label, to: t.to, icon: icons[t.to] ?? it.icon, perm: t.perm });
    else out.push({ section: s.label ?? "Keystone", label: it.label, to: it.to, icon: it.icon, perm: it.perm });
  }
  return out;
})();

/** Routes that exist in the current build; nav entries for others are hidden. */
export const BUILT = new Set<string>();
