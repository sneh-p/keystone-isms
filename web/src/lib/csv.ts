/** Minimal RFC 4180 CSV reader/writer for register import. Parsing happens in the browser; the server gets JSON. */

export const MAX_CSV_BYTES = 2_000_000;

/** Parses CSV text into rows of cells. Handles quoted fields, doubled quotes, CRLF/LF and a UTF-8 BOM. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  const sep = detectSeparator(text);
  for (; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { cell += '"'; i++; } else quoted = false;
      } else cell += ch;
    } else if (ch === '"' && cell === "") quoted = true;
    else if (ch === sep) { row.push(cell); cell = ""; }
    else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); cell = "";
      rows.push(row); row = [];
    } else cell += ch;
  }
  if (quoted) throw new Error("The file ends inside a quoted value.");
  if (cell !== "" || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((c) => c.trim() !== ""));
}

/** Spreadsheets in some locales save CSV with semicolons; use whichever separator the header row uses more. */
function detectSeparator(text: string): string {
  const first = text.slice(0, text.search(/\r?\n|$/));
  return (first.match(/;/g)?.length ?? 0) > (first.match(/,/g)?.length ?? 0) ? ";" : ",";
}

/** Header row plus data rows as objects keyed by the header. Rows with the wrong number of cells are an error. */
export function csvRecords(text: string): { headers: string[]; records: Record<string, string>[] } {
  const [headers, ...data] = parseCsv(text);
  if (!headers) throw new Error("The file is empty.");
  const bad = data.findIndex((r) => r.length !== headers.length);
  if (bad >= 0) throw new Error(`Row ${bad + 2} has ${data[bad].length} values but the header has ${headers.length}.`);
  return { headers, records: data.map((r) => Object.fromEntries(headers.map((h, i) => [h, r[i]]))) };
}

/** One CSV line; quotes values that need it. Cells starting with = + - @ are prefixed so spreadsheets show them as text. */
export function toCsvLine(cells: string[]): string {
  return cells.map((c) => {
    const v = /^[=+\-@\t\r]/.test(c) ? `'${c}` : c;
    return /[",\r\n;]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  }).join(",");
}
