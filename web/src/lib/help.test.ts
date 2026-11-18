import { describe, expect, it } from "vitest";
import { helpAnchorFor, PAGE_HELP, parseGuide, searchGuide, sectionFor, slugify, subsectionBody } from "./help";
import { GUIDE, HELP_IMAGES } from "./help-content";
import guideText from "../../../docs/user-guide.md?raw";

const allIds = new Set(GUIDE.sections.flatMap((s) => [s.id, ...s.subsections.map((h) => h.id)]));
// Every heading the page renders gets slugify(text) as its id, so duplicate heading texts would collide.
const headingIds = [...guideText.matchAll(/^#{2,4} (.+)$/gm)].map((m) => slugify(m[1].replace(/[`*_]/g, "")));

describe("the bundled user guide", () => {
  it("splits into the numbered sections, without the file's own contents list", () => {
    expect(GUIDE.sections[0].id).toBe("1-getting-started");
    expect(GUIDE.sections.map((s) => s.title)).toContain("6. Risk");
    expect(allIds.has("contents")).toBe(false);
    expect(GUIDE.sections.length).toBeGreaterThanOrEqual(12);
  });
  it("has unique heading anchors", () => {
    expect(headingIds.length).toBe(new Set(headingIds).size);
  });
  it("sends every screen's help button to a topic that exists", () => {
    for (const [path, id] of Object.entries(PAGE_HELP)) expect(allIds.has(id), `${path} → #${id}`).toBe(true);
  });
  it("resolves every link between topics", () => {
    for (const m of guideText.matchAll(/\]\(#([^)]+)\)/g)) expect(allIds.has(m[1]), `#${m[1]}`).toBe(true);
  });
  it("bundles every screenshot it shows", () => {
    const refs = [...guideText.matchAll(/!\[[^\]]*\]\(user-guide\/([^)]+)\)/g)].map((m) => m[1]);
    expect(refs.length).toBeGreaterThan(50);
    for (const r of refs) expect(HELP_IMAGES[r], r).toBeTruthy();
  });
});

describe("help lookups", () => {
  it("finds the section for a page, the longest path winning", () => {
    expect(helpAnchorFor("/")).toBe("4-overview");
    expect(helpAnchorFor("/risks")).toBe("risk-register");
    expect(helpAnchorFor("/settings/account")).toBe("your-account");
    expect(helpAnchorFor("/settings/users")).toBe("10-settings");
    expect(helpAnchorFor("/frameworks/ISO27001")).toBe("frameworks");
    expect(helpAnchorFor("/somewhere-else")).toBe("1-getting-started");
    expect(sectionFor(GUIDE, "risk-register")?.id).toBe("6-risk");
  });
  it("searches headings and text, every word required", () => {
    const hits = searchGuide(GUIDE, "custom checks");
    expect(hits[0].heading.id).toBe("configuration");
    expect(searchGuide(GUIDE, "x")).toEqual([]);
    expect(searchGuide(GUIDE, "zzqqxx nothing")).toEqual([]);
    expect(searchGuide(GUIDE, "segregation duties").length).toBeGreaterThan(0);
  });
  it("cuts out one topic", () => {
    expect(subsectionBody(GUIDE, "signing-in")).toMatch(/^### Signing in\n/);
    expect(subsectionBody(GUIDE, "signing-in")).not.toContain("### The guided tour");
  });
  it("ignores headings inside code blocks and numbers repeated titles like GitHub", () => {
    const g = parseGuide("# T\n\nIntro\n\n## A\n\n```\n## not a heading\n```\n\n### X\n\n## B\n\n### X\n");
    expect(g.intro).toBe("Intro");
    expect(g.sections.map((s) => s.id)).toEqual(["a", "b"]);
    expect(g.sections[1].subsections[0].id).toBe("x-1");
  });
});
