/**
 * The in-app help: docs/user-guide.md, split into its numbered sections. The guide is bundled at build time, so the
 * help in Keystone and the guide in the repository are always the same text.
 */

export type HelpHeading = { id: string; title: string };
export type HelpSection = HelpHeading & { body: string; subsections: HelpHeading[] };
export type HelpGuide = { intro: string; sections: HelpSection[] };
export type HelpHit = { section: HelpSection; heading: HelpHeading; snippet: string };

/** GitHub's heading anchors, so links written for the repository (`#risk-register`) work in the app too. */
export function slugify(text: string): string {
  return text.trim().toLowerCase().replace(/[`*_]/g, "").replace(/[^\w\- ]/g, "").replace(/ /g, "-");
}

/** Plain text of a heading: inline Markdown removed. */
function headingText(line: string): string {
  return line.replace(/^#+\s+/, "").replace(/[`*_]/g, "").trim();
}

/** Split the guide at its `## ` headings (outside code blocks), with each section's `### ` headings. */
export function parseGuide(md: string): HelpGuide {
  const seen = new Map<string, number>();
  const unique = (title: string) => {
    const base = slugify(title);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return n ? `${base}-${n}` : base;
  };
  const sections: HelpSection[] = [];
  const intro: string[] = [];
  let current: HelpSection | null = null;
  let fenced = false;
  for (const line of md.split("\n")) {
    if (line.startsWith("```")) fenced = !fenced;
    const level = fenced ? 0 : (/^(#{1,6}) /.exec(line)?.[1].length ?? 0);
    if (level === 2) {
      const title = headingText(line);
      current = { id: unique(title), title, body: "", subsections: [] };
      sections.push(current);
      continue;
    }
    if (level >= 1) {
      const title = headingText(line);
      const id = unique(title);
      if (level === 3 && current) current.subsections.push({ id, title });
    }
    if (current) current.body += line + "\n";
    else if (level !== 1) intro.push(line);
  }
  for (const s of sections) s.body = s.body.replace(/\n---\s*\n*$/, "\n").trim();
  // The guide's own table of contents is for readers of the file; the help page builds its own.
  return { intro: intro.join("\n").trim(), sections: sections.filter((s) => s.id !== "contents") };
}

/** The section a heading id belongs to (a section's own id or one of its subsections). */
export function sectionFor(guide: HelpGuide, id: string | null | undefined): HelpSection | undefined {
  if (!id) return undefined;
  return guide.sections.find((s) => s.id === id || s.subsections.some((h) => h.id === id));
}

/** Text of one `###` subsection, for showing a single topic (the employee portal's help, for example). */
export function subsectionBody(guide: HelpGuide, id: string): string | undefined {
  const s = sectionFor(guide, id);
  if (!s) return undefined;
  if (s.id === id) return s.body;
  const lines = s.body.split("\n");
  const start = lines.findIndex((l) => /^### /.test(l) && slugify(headingText(l)) === id);
  if (start < 0) return undefined;
  const end = lines.findIndex((l, i) => i > start && /^#{2,3} /.test(l));
  return lines.slice(start, end < 0 ? undefined : end).join("\n").trim();
}

function plain(md: string): string {
  return md
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")          // screenshots
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")        // links: keep their text
    .replace(/^\s*(?:[-*]|\d+\.)\s+/gm, "")          // list markers
    .replace(/^\s*\|?[-:| ]+\|?\s*$/gm, " ")          // table rules
    .replace(/[`*_>#]/g, "").replace(/\|/g, " · ")
    .replace(/\s+/g, " ").trim();
}

function occurrences(hay: string, word: string): number {
  let n = 0;
  for (let i = hay.indexOf(word); i >= 0; i = hay.indexOf(word, i + word.length)) n++;
  return n;
}

/** Find topics: every word must appear in the topic's heading or text. Headings that match rank first. */
export function searchGuide(guide: HelpGuide, query: string, limit = 12): HelpHit[] {
  const words = query.toLowerCase().split(/\s+/).filter((w) => w.length > 1);
  if (!words.length) return [];
  const hits: (HelpHit & { rank: number })[] = [];
  for (const section of guide.sections) {
    // Each subsection is a topic; the section's opening text (before its first subsection) is one too.
    const parts: { heading: HelpHeading; text: string }[] = [];
    let heading: HelpHeading = section;
    let buf: string[] = [];
    for (const line of section.body.split("\n")) {
      if (/^### /.test(line)) {
        parts.push({ heading, text: buf.join("\n") });
        heading = section.subsections.find((h) => h.title === headingText(line)) ?? { id: slugify(headingText(line)), title: headingText(line) };
        buf = [];
      } else buf.push(line);
    }
    parts.push({ heading, text: buf.join("\n") });
    for (const p of parts) {
      const text = plain(p.text);
      const hay = `${p.heading.title} ${text}`.toLowerCase();
      if (!words.every((w) => hay.includes(w))) continue;
      const at = Math.max(0, text.toLowerCase().indexOf(words[0]));
      const snippet = (at > 60 ? "…" : "") + text.slice(Math.max(0, at - 60), at + 140).trim() + (at + 140 < text.length ? "…" : "");
      // Headings that name the words first, then topics that use them most.
      const rank = 1000 * words.filter((w) => p.heading.title.toLowerCase().includes(w)).length + words.reduce((n, w) => n + occurrences(hay, w), 0);
      hits.push({ section, heading: p.heading, snippet, rank });
    }
  }
  return hits.sort((a, b) => b.rank - a.rank).slice(0, limit).map(({ rank: _rank, ...h }) => h);
}

/** Which part of the guide explains each screen: the longest matching path wins. */
export const PAGE_HELP: Record<string, string> = {
  "/": "4-overview",
  "/onboarding": "3-setting-up-the-isms",
  "/frameworks": "frameworks",
  "/controls": "controls",
  "/tasks": "tasks",
  "/calendar": "calendar",
  "/policies": "policies",
  "/evidence": "evidence",
  "/soa": "statement-of-applicability",
  "/privacy": "privacy",
  "/risks": "risk-register",
  "/assets": "assets",
  "/attack-surface": "attack-surface",
  "/configuration": "configuration",
  "/vendors": "vendors",
  "/questionnaires": "vendor-questionnaires",
  "/assessments": "vendor-assessments",
  "/exposure": "entra-exposure",
  "/people": "people-and-training",
  "/access-reviews": "access-reviews",
  "/trust-center": "trust-center",
  "/security-questionnaires": "customer-questionnaires",
  "/integrations": "integrations",
  "/incidents": "incidents",
  "/continuity": "business-continuity",
  "/nonconformities": "nonconformities",
  "/audits": "audits",
  "/reviews": "management-review",
  "/workload": "workload",
  "/reports": "reports",
  "/settings": "10-settings",
  "/settings/organisation": "3-setting-up-the-isms",
  "/settings/account": "your-account",
  "/help": "1-getting-started",
  "/registers/obligations": "legal-and-contract-obligations",
  "/exceptions": "exceptions",
  "/registers/policy-exceptions": "exceptions",
  "/registers/changes": "changes",
  "/registers/screening": "people-security",
  "/registers/confidentiality": "people-security",
  "/registers/sites": "physical-security",
  "/registers/physical-checks": "physical-security",
  "/registers/visitors": "physical-security",
  "/access-check": "leaver-access-check",
  "/security-reports": "security-reports",
  "/alerts": "alert-inbox",
  "/registers/pentests": "penetration-tests",
  "/registers/findings": "penetration-tests",
  "/registers/applications": "application-security",
  "/registers/threat-models": "application-security",
  "/registers/release-signoffs": "application-security",
  "/registers/crypto": "certificates-and-keys",
  "/registers/backups": "backup-assurance",
  "/indicators": "indicators-and-maturity",
  "/maturity": "indicators-and-maturity",
};

export function helpAnchorFor(pathname: string): string {
  const match = Object.keys(PAGE_HELP)
    .filter((p) => (p === "/" ? pathname === "/" : pathname === p || pathname.startsWith(p + "/")))
    .sort((a, b) => b.length - a.length)[0];
  return match ? PAGE_HELP[match] : "1-getting-started";
}
