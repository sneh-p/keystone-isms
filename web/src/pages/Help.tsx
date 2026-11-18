import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { ChevronLeft, ChevronRight, LifeBuoy, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { safeHref } from "@/lib/safe-url";
import { searchGuide, sectionFor, slugify, subsectionBody, type HelpSection } from "@/lib/help";
import { GUIDE, HELP_IMAGES } from "@/lib/help-content";
import { Input } from "@/components/ui/input";
import { Empty, PageHeader } from "@/components/ui/misc";
import { PortalShell } from "@/pages/Portal";

function textOf(children: ReactNode): string {
  if (typeof children === "string" || typeof children === "number") return String(children);
  if (Array.isArray(children)) return children.map(textOf).join("");
  if (children && typeof children === "object" && "props" in children) return textOf((children as { props: { children?: ReactNode } }).props.children);
  return "";
}

/**
 * The bundled user guide, rendered. Only its own screenshots are shown (never an image from elsewhere), headings get
 * the same anchors as on GitHub, links between topics stay in the app, and links to other repository files are
 * shown as text. `topicLinks` is off in the employee portal, which has no access to the full guide.
 */
export function HelpMarkdown({ children, topicLinks = true }: { children: string; topicLinks?: boolean }) {
  const heading = (Tag: "h2" | "h3" | "h4") => ({ children: c }: { children?: ReactNode }) => <Tag id={slugify(textOf(c))} className="scroll-mt-4">{c}</Tag>;
  return (
    <div className="prose-policy prose-help text-sm">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h2: heading("h2"), h3: heading("h3"), h4: heading("h4"),
          a: ({ href, children: c }) => {
            if (href?.startsWith("#")) return topicLinks ? <Link to={`/help${href}`} className="text-primary underline">{c}</Link> : <span>{c}</span>;
            const safe = href && /^https?:/.test(href) ? safeHref(href) : null;
            return safe ? <a href={safe} target="_blank" rel="noreferrer noopener" className="text-primary underline">{c}</a> : <span>{c}</span>;
          },
          img: ({ src, alt }) => {
            const url = src ? HELP_IMAGES[String(src).split("/").pop() ?? ""] : undefined;
            if (!url) return alt ? <span className="text-muted-foreground">[{alt}]</span> : null;
            return (
              <a href={url} target="_blank" rel="noreferrer" className="my-3 block" title="Open full size">
                {/* Screenshots are one screen each (desktop 1440 × 900, phone 390 × 844): reserving the space keeps
                    a topic where "Help for this page" scrolled to while the images load. */}
                <img src={url} alt={alt ?? ""} loading="lazy" className="h-auto w-full rounded-lg border shadow-sm"
                  width={String(src).includes("/phone") ? 390 : 1440} height={String(src).includes("/phone") ? 844 : 900} />
              </a>
            );
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}

function scrollToAnchor(id: string | null) {
  requestAnimationFrame(() => {
    const el = id ? document.getElementById(id) : null;
    if (el) el.scrollIntoView({ block: "start" });
    else document.getElementById("main")?.scrollTo({ top: 0 });
  });
}

/** Help: the user guide, one numbered section at a time, with contents, search and previous/next. */
export default function Help() {
  const { hash } = useLocation();
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const anchor = decodeURIComponent(hash.replace(/^#/, "")) || null;
  const section: HelpSection = sectionFor(GUIDE, anchor) ?? GUIDE.sections[0];
  const index = GUIDE.sections.indexOf(section);
  const hits = useMemo(() => (q.trim().length >= 2 ? searchGuide(GUIDE, q) : null), [q]);
  useEffect(() => { if (!hits) scrollToAnchor(anchor && anchor !== section.id ? anchor : null); }, [anchor, section.id, hits]);
  const go = (id: string) => { setQ(""); void nav(`/help#${id}`); };
  const prev = GUIDE.sections[index - 1], next = GUIDE.sections[index + 1];

  return (
    <div className="animate-fade-in">
      <PageHeader icon={LifeBuoy} title="Help" description="The Keystone user guide: what each screen is for and how to use it. The help button at the top of every page opens the part about that page." />
      <div className="grid gap-6 lg:grid-cols-[17rem_minmax(0,1fr)]">
        <div className="space-y-3 lg:sticky lg:top-0 lg:max-h-[calc(100vh-9rem)] lg:overflow-y-auto">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" aria-hidden />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search help…" className="pl-8" aria-label="Search help" />
          </div>
          <nav aria-label="Help contents">
            <details className="group rounded-lg border lg:border-0" open>
              <summary className="cursor-pointer list-none px-3 py-2 text-sm font-medium lg:hidden">Contents</summary>
              <ol className="space-y-0.5 p-1 lg:p-0">
                {GUIDE.sections.map((s) => (
                  <li key={s.id}>
                    <Link to={`/help#${s.id}`} onClick={() => setQ("")} aria-current={s.id === section.id && !hits ? "page" : undefined}
                      className={cn("block rounded-md px-3 py-1.5 text-sm", s.id === section.id && !hits ? "bg-sidebar-active font-medium text-accent-foreground" : "text-sidebar-foreground hover:bg-muted")}>
                      {s.title}
                    </Link>
                    {s.id === section.id && !hits && s.subsections.length > 0 && (
                      <ul className="my-1 ml-3 space-y-0.5 border-l pl-2">
                        {s.subsections.map((h) => (
                          <li key={h.id}><Link to={`/help#${h.id}`} className={cn("block rounded px-2 py-1 text-xs hover:bg-muted", anchor === h.id ? "font-medium text-foreground" : "text-muted-foreground")}>{h.title}</Link></li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ol>
            </details>
          </nav>
        </div>

        <div className="min-w-0">
          {hits ? (
            <section aria-label="Search results" className="space-y-2">
              <p className="text-sm text-muted-foreground" aria-live="polite">{hits.length ? `${hits.length} topic${hits.length === 1 ? "" : "s"} found` : ""}</p>
              {hits.length === 0 ? <Empty title="Nothing found">Try another word, or browse the contents.</Empty> : hits.map((h) => (
                <button key={`${h.section.id}-${h.heading.id}`} type="button" onClick={() => go(h.heading.id)}
                  className="block w-full rounded-lg border bg-card p-3 text-left hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                  <span className="block text-sm font-medium">{h.heading.title}</span>
                  {h.heading.id !== h.section.id && <span className="block text-xs text-muted-foreground">{h.section.title}</span>}
                  <span className="mt-1 block text-xs text-muted-foreground">{h.snippet}</span>
                </button>
              ))}
            </section>
          ) : (
            <article className="rounded-lg border bg-card p-5 sm:p-8">
              <h2 id={section.id} className="mb-4 text-xl font-semibold tracking-tight">{section.title}</h2>
              <HelpMarkdown>{section.body}</HelpMarkdown>
              <div className="mt-8 flex flex-wrap justify-between gap-3 border-t pt-4 text-sm">
                {prev ? <Link to={`/help#${prev.id}`} className="inline-flex items-center gap-1 text-primary hover:underline"><ChevronLeft className="size-4" /> {prev.title}</Link> : <span />}
                {next && <Link to={`/help#${next.id}`} className="inline-flex items-center gap-1 text-primary hover:underline">{next.title} <ChevronRight className="size-4" /></Link>}
              </div>
            </article>
          )}
        </div>
      </div>
    </div>
  );
}

/** The employee portal's help: signing in and the portal section of the guide. */
export function PortalHelp() {
  const portal = GUIDE.sections.find((s) => s.id === "11-the-employee-portal");
  const signIn = subsectionBody(GUIDE, "signing-in");
  return (
    <PortalShell>
      <Link to="/portal" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ChevronLeft className="size-4" /> Back to the portal</Link>
      <h1 className="text-2xl font-semibold">Help</h1>
      <p className="mt-1 text-muted-foreground">How the employee portal works. For anything else, ask your security team.</p>
      <article className="mt-6 space-y-8 rounded-lg border bg-card p-5 sm:p-8">
        {portal && <HelpMarkdown topicLinks={false}>{portal.body}</HelpMarkdown>}
        {signIn && <HelpMarkdown topicLinks={false}>{signIn.replace(/^### Signing in/, "### Signing in and passwords")}</HelpMarkdown>}
      </article>
    </PortalShell>
  );
}
