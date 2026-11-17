import { describe, expect, it } from "vitest";
import { isShown, placeCard } from "./tour";

const vp = { width: 1440, height: 900 };
const card = { width: 352, height: 220 };

describe("placeCard", () => {
  it("centres the card when there is no target", () => {
    expect(placeCard(null, card, vp)).toEqual({ top: 340, left: 544, side: "center" });
  });
  it("puts the card right of a sidebar item, kept inside the viewport", () => {
    const p = placeCard({ top: 850, left: 8, width: 240, height: 30 }, card, vp);
    expect(p.side).toBe("right");
    expect(p.left).toBe(262);
    expect(p.top).toBe(900 - 220 - 16);
  });
  it("falls back to below, above, then left", () => {
    expect(placeCard({ top: 10, left: 1200, width: 200, height: 36 }, card, vp).side).toBe("bottom");
    expect(placeCard({ top: 800, left: 1200, width: 200, height: 36 }, card, vp).side).toBe("top");
    expect(placeCard({ top: 0, left: 1000, width: 400, height: 900 }, card, vp).side).toBe("left");
  });
  it("centres when nothing fits, as on a phone with a full-width target", () => {
    expect(placeCard({ top: 0, left: 0, width: 390, height: 844 }, card, { width: 390, height: 844 }).side).toBe("center");
  });
});

describe("isShown", () => {
  it("rejects hidden and off-screen elements", () => {
    expect(isShown({ top: 0, left: 0, width: 0, height: 0 }, vp)).toBe(false);
    expect(isShown({ top: 950, left: 10, width: 10, height: 10 }, vp)).toBe(false);
    expect(isShown({ top: 10, left: 10, width: 10, height: 10 }, vp)).toBe(true);
    expect(isShown(null, vp)).toBe(false);
  });
});
