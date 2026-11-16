import { describe, expect, it } from "vitest";
import { csvRecords, parseCsv, toCsvLine } from "./csv";

describe("parseCsv", () => {
  it("reads quoted fields, doubled quotes, CRLF and a BOM", () => {
    expect(parseCsv('﻿name,notes\r\n"Acme, Inc.","He said ""hi""\nthen left"\r\nB,\r\n')).toEqual([
      ["name", "notes"], ["Acme, Inc.", 'He said "hi"\nthen left'], ["B", ""],
    ]);
  });
  it("detects semicolon-separated files and skips blank lines", () => {
    expect(parseCsv("a;b\n\n1;2,5\n")).toEqual([["a", "b"], ["1", "2,5"]]);
  });
  it("rejects an unterminated quote", () => {
    expect(() => parseCsv('a\n"oops')).toThrow(/quoted/);
  });
});

describe("csvRecords", () => {
  it("maps rows to the header and rejects ragged rows", () => {
    expect(csvRecords("name,owner\nX,ada\n").records).toEqual([{ name: "X", owner: "ada" }]);
    expect(() => csvRecords("name,owner\nX\n")).toThrow(/Row 2 has 1 values/);
  });
});

describe("toCsvLine", () => {
  it("quotes separators and neutralises formulas", () => {
    expect(toCsvLine(["a,b", '=HYPERLINK("x")', "plain"])).toBe(`"a,b","'=HYPERLINK(""x"")",plain`);
  });
});
