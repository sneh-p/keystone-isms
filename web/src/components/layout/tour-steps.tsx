import type { TourStep } from "@/components/Tour";

/** `data-tour` name for a sidebar section: its label, or its only item's label ("Overview", "Settings"). */
export function sectionTourName(label: string | undefined, firstItem: string): string {
  return `nav-${(label ?? firstItem).toLowerCase().replace(/[^a-z]+/g, "-").replace(/^-|-$/g, "")}`;
}

const SECTIONS: Record<string, { title: string; body: string }> = {
  "nav-overview": { title: "Overview", body: "Your starting point: the next steps that move readiness most, headline figures with 12-week trends, framework readiness, the risk heat map and what needs attention." },
  "nav-compliance": { title: "Compliance", body: "Frameworks and their readiness, the controls behind them, recurring evidence tasks, the calendar, policies, evidence, the Statement of Applicability and privacy records." },
  "nav-risk": { title: "Risk", body: "The risk register with treatment and acceptance, the asset register, the attack surface your tools report, and configuration baselines for hosts and firewalls." },
  "nav-third-parties": { title: "Third parties", body: "Vendors with tiering, questionnaires and assessments, and the third-party apps that have access to your Microsoft 365 tenant." },
  "nav-trust-and-people": { title: "Trust and people", body: "People and their training, access reviews, your public Trust Center, customer security questionnaires and integrations." },
  "nav-operations": { title: "Operations", body: "Incidents, business continuity, nonconformities, internal audits and management review, everyone's workload, and reports." },
  "nav-settings": { title: "Settings", body: "Your organisation, and depending on your role: users and roles, single sign-on, email, chat and webhooks, AI, the audit log and system health." },
};

/**
 * The staff tour. Sidebar sections the user can't see are left out; on a phone, where the sidebar is behind the
 * menu button, the sections become one step.
 */
export function appTourSteps(firstName: string, sections: string[], phone: boolean): TourStep[] {
  const known = sections.filter((s) => SECTIONS[s]);
  const nav: TourStep[] = phone
    ? [{ target: "menu", title: "The menu", body: <><p>Everything in Keystone is one tap away here, grouped by what it's for:</p><ul className="list-disc space-y-0.5 pl-5">{known.map((s) => <li key={s}><span className="font-medium text-foreground">{SECTIONS[s].title}</span></li>)}</ul></> }]
    : known.map((s) => ({ target: s, title: SECTIONS[s].title, body: SECTIONS[s].body }));
  return [
    { title: `Welcome to Keystone${firstName ? `, ${firstName}` : ""}`, body: <><p>Keystone runs your information security management system: risks, controls and evidence, policies, people, suppliers, incidents and audits, in one place.</p><p>This short tour shows where things are. You can end it at any time, and take it again from your name in the top-right corner.</p></> },
    { target: "search", title: "Search or jump to", body: <p>Open any page, or find a record by its reference (for example <span className="font-mono text-foreground">RSK-0004</span>) or its title. Press <kbd className="rounded border bg-muted px-1 text-xs">Ctrl</kbd> + <kbd className="rounded border bg-muted px-1 text-xs">K</kbd> (<kbd className="rounded border bg-muted px-1 text-xs">⌘</kbd> + <kbd className="rounded border bg-muted px-1 text-xs">K</kbd> on a Mac) from anywhere.</p> },
    ...nav,
    { target: "help", title: "Help", body: <p>Opens the user guide at the part about the page you're on: what it's for and how to use it, with screenshots. You can also search the whole guide, or find it in your name menu.</p> },
    { target: "notifications", title: "Notifications", body: <p>Work that needs you lands here: tasks due, reviews, approvals, @mentions and findings on records you own. A daily email digest is optional, and you choose which kinds it includes.</p> },
    { target: "account", title: "Your account", body: <p>Change your password, open your employee portal to accept policies and complete training, sign out, or <span className="font-medium text-foreground">take this tour again</span>.</p> },
    { title: "You're ready", body: <><p>Each page explains itself at the top. Click a row to open the record in a side panel with its history, comments and links to related records.</p><p>Tables can be searched, filtered and exported to CSV.</p></> },
  ];
}

/** The employee portal tour. */
export const PORTAL_TOUR: TourStep[] = [
  { title: "Welcome to your employee portal", body: <p>A few things keep you and the company secure. This portal lists what's left for you to do. The tour takes under a minute.</p> },
  { target: "portal-progress", title: "Your progress", body: <p>How much of your security to-do list is done. When it reaches the end, you're all set until something new needs you.</p> },
  { target: "portal-policies", title: "Policies to accept", body: <p>Read each policy and sign by typing your full name. A new version of a policy may ask you to accept it again.</p> },
  { target: "portal-training", title: "Security training", body: <p>Short modules with a quiz at the end. A pass lasts a year; due dates are shown on each module.</p> },
  { target: "portal-devices", title: "Device security", body: <p>Confirm that each work device meets the basics: updates, encryption, screen lock and so on. Renew it every six months.</p> },
  { target: "portal-notifications", title: "Notifications", body: <p>Reminders about anything due appear here, and in a daily email if you choose.</p> },
];
