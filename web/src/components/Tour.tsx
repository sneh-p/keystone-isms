import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { isShown, placeCard, type Placement, type Rect } from "@/lib/tour";
import { Button } from "@/components/ui/button";

/** One stop on a tour. `target` names an element's `data-tour` attribute; without one (or when it's hidden) the card is centred. */
export type TourStep = { target?: string; title: string; body: ReactNode };
export type TourKey = "app" | "portal";
type TourState = Record<TourKey, { version: number; seen: boolean; outcome: string | null }>;

/** Whether the signed-in user has finished or ended a tour, and a way to record it (stored per user on the server). */
export function useTourState(key: TourKey) {
  const qc = useQueryClient();
  const { data } = useApi<TourState>("/portal/tours");
  const record = useCallback((outcome: "completed" | "skipped") => {
    api<TourState>(`/portal/tours/${key}`, { method: "PUT", body: { outcome } })
      .then((d) => qc.setQueryData(["/portal/tours"], d), () => { /* the tour may show again next time: harmless */ });
  }, [key, qc]);
  return { loaded: !!data, seen: data ? data[key].seen : true, record };
}

const PAD = 6;
const FOCUSABLE = "button:not([disabled]), [href], [tabindex]:not([tabindex='-1'])";

function viewport() {
  return { width: window.innerWidth, height: window.innerHeight };
}

function targetRect(name?: string): Rect | null {
  if (!name) return null;
  const el = document.querySelector<HTMLElement>(`[data-tour="${name}"]`);
  if (!el) return null;
  const r = el.getBoundingClientRect();
  return isShown(r, viewport()) ? { top: r.top - PAD, left: r.left - PAD, width: r.width + 2 * PAD, height: r.height + 2 * PAD } : null;
}

/**
 * A guided tour: a dimmed page with the current element cut out, and a card beside it. Keyboard: Tab stays in the
 * card, → / ← move between steps, Escape ends the tour. The page underneath can't be clicked while the tour runs.
 * `onEnd(true)` means the user reached the last step; `onEnd(false)` means they ended it early.
 */
export function Tour({ steps, onEnd, label = "Guided tour" }: { steps: TourStep[]; onEnd: (completed: boolean) => void; label?: string }) {
  const [i, setI] = useState(0);
  const [rect, setRect] = useState<Rect | null>(null);
  const [place, setPlace] = useState<Placement | null>(null);
  const card = useRef<HTMLDivElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const returnFocus = useRef<Element | null>(null);
  const step = steps[Math.min(i, steps.length - 1)];
  const last = i >= steps.length - 1;

  const measure = useCallback(() => {
    const r = targetRect(step.target);
    setRect(r);
    const c = card.current;
    if (c) setPlace(placeCard(r, { width: c.offsetWidth, height: c.offsetHeight }, viewport()));
  }, [step.target]);

  // Bring the target into view, then place the card once its size is known.
  useLayoutEffect(() => {
    if (step.target) document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`)?.scrollIntoView({ block: "nearest", inline: "nearest" });
    setPlace(null);
    measure();
  }, [measure, step.target]);

  useEffect(() => {
    let frame = 0;
    const later = () => { cancelAnimationFrame(frame); frame = requestAnimationFrame(measure); };
    window.addEventListener("resize", later);
    window.addEventListener("scroll", later, true);
    return () => { cancelAnimationFrame(frame); window.removeEventListener("resize", later); window.removeEventListener("scroll", later, true); };
  }, [measure]);

  // The app underneath is inert while the tour runs (screen readers and Tab stay in the card). Declared first so it
  // is lifted before focus goes back to where it was.
  useEffect(() => {
    const root = document.getElementById("root");
    root?.setAttribute("inert", "");
    return () => root?.removeAttribute("inert");
  }, []);
  useEffect(() => {
    returnFocus.current = document.activeElement;
    return () => { (returnFocus.current as HTMLElement | null)?.focus?.(); };
  }, []);
  useEffect(() => { heading.current?.focus(); }, [i]);

  const end = (completed: boolean) => onEnd(completed);
  const next = () => (last ? end(true) : setI(i + 1));
  const back = () => setI(Math.max(0, i - 1));

  // Keys are handled on the whole document, so they work wherever focus is. Tab is kept inside the card.
  const onKey = (e: globalThis.KeyboardEvent) => {
    if (e.key === "Escape") { e.preventDefault(); end(false); return; }
    if (e.key === "ArrowRight") { e.preventDefault(); next(); return; }
    if (e.key === "ArrowLeft") { e.preventDefault(); back(); return; }
    if (e.key === "Tab" && card.current) {
      const items = [...card.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (!items.length) return;
      const first = items[0], lastItem = items[items.length - 1];
      const at = document.activeElement;
      if (!card.current.contains(at)) { e.preventDefault(); (e.shiftKey ? lastItem : first).focus(); }
      else if (e.shiftKey && (at === first || at === heading.current)) { e.preventDefault(); lastItem.focus(); }
      else if (!e.shiftKey && at === lastItem) { e.preventDefault(); first.focus(); }
    }
  };
  const keyHandler = useRef(onKey);
  keyHandler.current = onKey;
  useEffect(() => {
    const fn = (e: globalThis.KeyboardEvent) => keyHandler.current(e);
    document.addEventListener("keydown", fn, true);
    return () => document.removeEventListener("keydown", fn, true);
  }, []);

  return createPortal(
    <div className="fixed inset-0 z-[60]">
      {/* The dimmed page: a cut-out around the target, or a plain scrim when the card is centred. Clicks go nowhere. */}
      {rect ? (
        <div aria-hidden className="pointer-events-none fixed rounded-lg ring-2 ring-primary motion-safe:transition-all motion-safe:duration-200"
          style={{ top: rect.top, left: rect.left, width: rect.width, height: rect.height, boxShadow: "0 0 0 9999px rgb(0 0 0 / 0.55)" }} />
      ) : <div aria-hidden className="fixed inset-0 bg-black/55" />}
      <div aria-hidden className="fixed inset-0" onMouseDown={(e) => e.preventDefault()} />
      <div ref={card} role="dialog" aria-modal="true" aria-label={label} aria-describedby="tour-body"
        className="fixed w-[min(22rem,calc(100vw-2rem))] rounded-lg border bg-popover p-4 text-popover-foreground shadow-2xl motion-safe:transition-[top,left] motion-safe:duration-200"
        style={{ top: place?.top ?? -9999, left: place?.left ?? -9999, visibility: place ? "visible" : "hidden" }}>
        <div className="flex items-start justify-between gap-3">
          <p className="text-xs font-medium text-muted-foreground" aria-live="polite">Step {i + 1} of {steps.length}</p>
          <button type="button" onClick={() => end(false)} aria-label="End tour" className="-m-1 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <X className="size-4" />
          </button>
        </div>
        <h2 ref={heading} tabIndex={-1} className="mt-1 text-base font-semibold focus:outline-none">{step.title}</h2>
        <div id="tour-body" className="mt-1.5 space-y-2 text-sm text-muted-foreground">{step.body}</div>
        <div className="mt-3 flex gap-1" aria-hidden>
          {steps.map((_, j) => <span key={j} className={`h-1 flex-1 rounded-full ${j <= i ? "bg-primary" : "bg-muted"}`} />)}
        </div>
        <div className="mt-4 flex items-center justify-between gap-2">
          <Button variant="ghost" size="sm" onClick={() => end(false)}>{i === 0 ? "Skip tour" : "End tour"}</Button>
          <div className="flex gap-2">
            {i > 0 && <Button variant="outline" size="sm" onClick={back}>Back</Button>}
            <Button size="sm" onClick={next}>{last ? "Finish" : i === 0 ? "Start tour" : "Next"}</Button>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}
