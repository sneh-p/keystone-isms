import {
  Activity, AlertOctagon, BookOpen, Boxes, Building2, ClipboardCheck, ClipboardList, FileCheck2, FileText, Gauge, Globe2, Handshake, KeyRound,
  LayoutDashboard, ListChecks, Map as MapIcon, Paperclip, Plug, ScrollText, Search, Settings, ShieldCheck, Siren, UserCog, Users, Wrench, Scale,
} from "lucide-react";

export type NavItem = { label: string; to: string; icon: any; perm?: string };
export type NavSection = { label?: string; items: NavItem[] };

export const NAV: NavSection[] = [
  { items: [{ label: "Overview", to: "/", icon: LayoutDashboard }] },
  {
    label: "Compliance",
    items: [
      { label: "Frameworks", to: "/frameworks", icon: BookOpen },
      { label: "Controls", to: "/controls", icon: ShieldCheck },
      { label: "Tasks", to: "/tasks", icon: ListChecks },
      { label: "Policies", to: "/policies", icon: ScrollText },
      { label: "Evidence", to: "/evidence", icon: Paperclip },
      { label: "Statement of Applicability", to: "/soa", icon: FileCheck2 },
    ],
  },
  {
    label: "Risk",
    items: [
      { label: "Risk register", to: "/risks", icon: Gauge },
      { label: "Assets", to: "/assets", icon: Boxes },
    ],
  },
  {
    label: "Third parties",
    items: [
      { label: "Vendors", to: "/vendors", icon: Handshake },
      { label: "Questionnaires", to: "/questionnaires", icon: ClipboardList },
      { label: "Vendor assessments", to: "/assessments", icon: Scale },
      { label: "Entra exposure", to: "/exposure", icon: MapIcon },
    ],
  },
  {
    label: "Trust & people",
    items: [
      { label: "People", to: "/people", icon: Users },
      { label: "Trust Center", to: "/trust-center", icon: Globe2 },
      { label: "Security questionnaires", to: "/security-questionnaires", icon: FileText },
      { label: "Integrations", to: "/integrations", icon: Plug },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Incidents", to: "/incidents", icon: Siren },
      { label: "Nonconformities", to: "/nonconformities", icon: Wrench },
      { label: "Audits", to: "/audits", icon: Search },
      { label: "Management review", to: "/reviews", icon: ClipboardCheck },
      { label: "Reports", to: "/reports", icon: Activity },
    ],
  },
  {
    label: "Settings",
    items: [
      { label: "Organisation", to: "/settings/organisation", icon: Building2 },
      { label: "Users", to: "/settings/users", icon: UserCog, perm: "users.manage" },
      { label: "Audit log", to: "/settings/audit-log", icon: AlertOctagon, perm: "audit_log.view" },
      { label: "My account", to: "/settings/account", icon: KeyRound },
      { label: "AI", to: "/settings/ai", icon: Settings, perm: "org.write" },
    ],
  },
];

/** Routes that exist in the current build; nav entries for others are hidden. */
export const BUILT = new Set<string>();
