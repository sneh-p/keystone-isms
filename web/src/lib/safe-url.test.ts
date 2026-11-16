import { describe, expect, it } from "vitest";
import { safeHref, safeRedirectPath } from "./safe-url";

describe("safeHref (SC-XSS-002)", () => {
  it("keeps web, mail and same-origin links", () => {
    expect(safeHref("https://example.com/a?b=1")).toBe("https://example.com/a?b=1");
    expect(safeHref("http://example.com/")).toBe("http://example.com/");
    expect(safeHref("mailto:security@example.com")).toBe("mailto:security@example.com");
    expect(safeHref("/exposure")).toBe("/exposure");
    expect(safeHref("#section")).toBe("#section");
  });

  it("drops script-capable and odd schemes", () => {
    for (const bad of ["javascript:alert(1)", " JavaScript:alert(1)", "java\tscript:alert(1)", "data:text/html,<script>alert(1)</script>", "vbscript:x", "file:///etc/passwd", "//evil.example/x", "/\\evil.example", "not a url", 42, null]) {
      expect(safeHref(bad)).toBeUndefined();
    }
  });
});

describe("safeRedirectPath (SC-XSS-005)", () => {
  it("allows only same-origin paths", () => {
    expect(safeRedirectPath("/risks?open=1")).toBe("/risks?open=1");
    for (const bad of ["https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)", "", undefined, { pathname: "/x" }]) {
      expect(safeRedirectPath(bad)).toBe("/");
    }
  });
});
