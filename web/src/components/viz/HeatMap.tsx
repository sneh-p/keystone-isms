import { cn } from "@/lib/utils";

const FILL: Record<string, string> = { Low: "bg-good text-[#0b0b0b]", Medium: "bg-warning text-[#0b0b0b]", High: "bg-serious text-[#0b0b0b]", Critical: "bg-critical text-white" };

/** 5x5 risk heat map. grid[impact-1][likelihood-1] = count; levels[impact-1][likelihood-1] = level.
 *  Each cell carries the count and the level initial, plus a tooltip, so colour is never the only cue. */
export function HeatMap({ grid, levels, title, likelihood, impact, onCell }: { grid: number[][]; levels: string[][]; title: string; likelihood?: Record<string, string>; impact?: Record<string, string>; onCell?: (l: number, i: number) => void }) {
  return (
    <figure>
      <figcaption className="mb-2 text-sm font-medium">{title}</figcaption>
      <div className="flex gap-2">
        <div className="flex items-center">
          <span className="-rotate-90 whitespace-nowrap text-[11px] text-muted-foreground">Impact →</span>
        </div>
        <div>
          <div className="grid grid-cols-[1.25rem_repeat(5,minmax(2.5rem,3.25rem))] gap-[2px]">
            {[5, 4, 3, 2, 1].map((im) => (
              <div key={im} className="contents">
                <div className="grid place-items-center text-[11px] text-muted-foreground" title={impact?.[im]}>{im}</div>
                {[1, 2, 3, 4, 5].map((lk) => {
                  const lv = levels[im - 1][lk - 1];
                  const n = grid[im - 1][lk - 1];
                  return (
                    <button
                      key={lk}
                      type="button"
                      onClick={() => onCell?.(lk, im)}
                      title={`Likelihood ${lk}${likelihood ? ` (${likelihood[lk]})` : ""} × Impact ${im}${impact ? ` (${impact[im]})` : ""} = ${lk * im}: ${lv}. ${n} risk(s).`}
                      className={cn("relative grid aspect-square place-items-center rounded-[4px] text-sm font-semibold transition-transform hover:scale-[1.04]", FILL[lv], !onCell && "cursor-default")}
                    >
                      {n || ""}
                      <span className="absolute bottom-0.5 right-1 text-[10px] font-semibold">{lv[0]}</span>
                    </button>
                  );
                })}
              </div>
            ))}
            <div />
            {[1, 2, 3, 4, 5].map((lk) => (
              <div key={lk} className="text-center text-[11px] text-muted-foreground" title={likelihood?.[lk]}>{lk}</div>
            ))}
          </div>
          <div className="mt-1 text-center text-[11px] text-muted-foreground">Likelihood →</div>
        </div>
      </div>
    </figure>
  );
}
