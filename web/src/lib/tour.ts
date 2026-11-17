/** Placement maths for the guided tour, kept free of the DOM so it can be tested. */

export type Rect = { top: number; left: number; width: number; height: number };
export type Placement = { top: number; left: number; side: "right" | "bottom" | "top" | "left" | "center" };

/**
 * Where the tour's card goes: beside the highlighted element if it fits (right, then below, above, left), otherwise
 * centred. The card is always kept `margin` pixels inside the viewport.
 */
export function placeCard(target: Rect | null, card: { width: number; height: number }, viewport: { width: number; height: number }, gap = 14, margin = 16): Placement {
  const clampX = (x: number) => Math.max(margin, Math.min(x, viewport.width - card.width - margin));
  const clampY = (y: number) => Math.max(margin, Math.min(y, viewport.height - card.height - margin));
  const center: Placement = { top: clampY((viewport.height - card.height) / 2), left: clampX((viewport.width - card.width) / 2), side: "center" };
  if (!target) return center;
  const right = target.left + target.width + gap;
  if (right + card.width + margin <= viewport.width) return { top: clampY(target.top), left: right, side: "right" };
  const below = target.top + target.height + gap;
  if (below + card.height + margin <= viewport.height) return { top: below, left: clampX(target.left), side: "bottom" };
  const above = target.top - gap - card.height;
  if (above >= margin) return { top: above, left: clampX(target.left), side: "top" };
  const left = target.left - gap - card.width;
  if (left >= margin) return { top: clampY(target.top), left, side: "left" };
  return center;
}

/** True when an element is laid out and at least partly inside the viewport (hidden sidebars report a zero size). */
export function isShown(r: Rect | null, viewport: { width: number; height: number }): r is Rect {
  return !!r && r.width > 0 && r.height > 0 && r.left < viewport.width && r.top < viewport.height && r.left + r.width > 0 && r.top + r.height > 0;
}
