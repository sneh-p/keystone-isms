import { describe, expect, it } from "vitest";

import { describeExpected, expectedFromInput, expectedToInput, resultLabel } from "./configcheck";

const OPS = { is_true: "is on", lte: "at most", in: "is one of" };

describe("rule values", () => {
  it("round-trips the value box", () => {
    expect(expectedToInput(["no", "prohibit-password"])).toBe("no, prohibit-password");
    expect(expectedToInput(null)).toBe("");
    expect(expectedFromInput({ type: "str" }, "in", "no, prohibit-password ,")).toEqual(["no", "prohibit-password"]);
    expect(expectedFromInput({ type: "int" }, "lte", " 15 ")).toBe(15);
    expect(expectedFromInput({ type: "int" }, "lte", "soon")).toBe("soon"); // the server explains what's wrong
    expect(expectedFromInput({ type: "bool" }, "is_true", "anything")).toBeNull();
  });
  it("describes requirements and results in words", () => {
    expect(describeExpected(OPS, "is_true", null)).toBe("is on");
    expect(describeExpected(OPS, "lte", 15)).toBe("at most 15");
    expect(describeExpected(OPS, "in", ["no", "yes"])).toBe("is one of no, yes");
    expect(resultLabel("na")).toBe("Not applicable");
    expect(resultLabel("unknown")).toBe("Unknown");
  });
});
