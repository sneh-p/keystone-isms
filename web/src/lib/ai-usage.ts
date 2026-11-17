export interface UsageTotals { calls: number; input_tokens: number; cache_write_tokens: number; cache_read_tokens: number; output_tokens: number }

/** Totals plus the share of input read from the prompt cache (cache reads cost a fraction of normal input). */
export function usageSummary(u: UsageTotals): string {
  const input = u.input_tokens + u.cache_write_tokens + u.cache_read_tokens;
  const cached = input > 0 ? Math.round((u.cache_read_tokens / input) * 100) : 0;
  return `${u.calls} call(s) · ${input.toLocaleString()} input tokens (${cached}% from cache) and ${u.output_tokens.toLocaleString()} output tokens in total`;
}
