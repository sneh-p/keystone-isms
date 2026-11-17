import { describe, expect, it } from "vitest";

import { usageSummary } from "./ai-usage";

describe("usageSummary", () => {
  it("counts cache reads and writes as input and shows the cached share", () => {
    expect(usageSummary({ calls: 2, input_tokens: 1000, cache_write_tokens: 3000, cache_read_tokens: 6000, output_tokens: 500 }))
      .toBe("2 call(s) · 10,000 input tokens (60% from cache) and 500 output tokens in total");
  });
  it("handles no calls", () => {
    expect(usageSummary({ calls: 0, input_tokens: 0, cache_write_tokens: 0, cache_read_tokens: 0, output_tokens: 0 })).toContain("(0% from cache)");
  });
});
