import { describe, expect, it } from "vitest";

import { allowedTypes, describeExpected, expectedFromInput, expectedToInput, parseList, parseTags, resultLabel, type Probe } from "./configcheck";

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


describe("custom check form helpers", () => {
  it("parses tags and patterns", () => {
    expect(parseTags("web, DMZ ,,web")).toEqual(["web", "dmz"]);
    expect(parseList("DB-*, web-0?")).toEqual(["DB-*", "web-0?"]);
  });
  it("offers the value types of the chosen mode", () => {
    const probe = { key: "registry_value", mode_param: "mode", types: { value: ["int", "str"], exists: ["bool"] } } as unknown as Probe;
    expect(allowedTypes(probe, { mode: "exists" })).toEqual(["bool"]);
    expect(allowedTypes(probe, { mode: "value" })).toEqual(["int", "str"]);
    expect(allowedTypes(probe, {})).toEqual([]);
    expect(allowedTypes(undefined, {})).toEqual([]);
  });
});
