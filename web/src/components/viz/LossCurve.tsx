import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtMoney, fmtNum } from "@/lib/utils";

/** FAIR loss exceedance curve. Loaded on demand (the chart library is large and only the FAIR tab needs it). */
export default function LossCurve({ data }: { data: { loss: number; p: number }[] }) {
  return (
    <ResponsiveContainer>
      <AreaChart data={data} margin={{ left: 8, right: 8, top: 8 }}>
        <CartesianGrid strokeDasharray="0" stroke="hsl(var(--border))" vertical={false} />
        <XAxis dataKey="loss" tickFormatter={fmtNum} tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} stroke="hsl(var(--border))" />
        <YAxis unit="%" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} stroke="hsl(var(--border))" width={40} />
        <Tooltip formatter={(v: any) => [`${v}%`, "Probability"]} labelFormatter={(l: any) => `Loss ≥ ${fmtMoney(l)}`} contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
        <Area type="monotone" dataKey="p" stroke="hsl(var(--primary))" strokeWidth={2} fill="hsl(var(--primary))" fillOpacity={0.12} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
