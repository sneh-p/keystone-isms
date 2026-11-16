import * as P from "@radix-ui/react-popover";
import { Command } from "cmdk";
import { Check, ChevronsUpDown, X } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Option } from "./select";

export function MultiSelect({ value, onChange, options, placeholder = "Select…" }: { value: string[]; onChange: (v: string[]) => void; options: Option[]; placeholder?: string }) {
  const labels = new Map(options.map((o) => [o.value, o.label]));
  const toggle = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  return (
    <P.Root>
      <P.Trigger className="flex min-h-9 w-full flex-wrap items-center gap-1 rounded-md border border-input bg-card px-2 py-1 text-left text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-ring">
        {value.length === 0 && <span className="px-1 text-muted-foreground">{placeholder}</span>}
        {value.map((v) => (
          <span key={v} className="inline-flex items-center gap-1 rounded bg-secondary px-1.5 py-0.5 text-xs">
            {labels.get(v) ?? v}
            <X
              className="size-3 cursor-pointer opacity-60 hover:opacity-100"
              onClick={(e) => {
                e.stopPropagation();
                toggle(v);
              }}
            />
          </span>
        ))}
        <ChevronsUpDown className="ml-auto size-4 opacity-50" />
      </P.Trigger>
      <P.Portal>
        <P.Content align="start" sideOffset={4} className="z-50 w-[var(--radix-popover-trigger-width)] min-w-64 rounded-md border bg-popover shadow-lg animate-fade-in">
          <Command className="text-sm">
            <Command.Input placeholder="Search…" className="w-full border-b bg-transparent px-3 py-2 outline-none" />
            <Command.List className="max-h-64 overflow-auto p-1">
              <Command.Empty className="px-3 py-4 text-center text-muted-foreground">No matches</Command.Empty>
              {options.map((o) => (
                <Command.Item key={o.value} value={o.label} onSelect={() => toggle(o.value)} className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 data-[selected=true]:bg-muted">
                  <Check className={cn("size-3.5", value.includes(o.value) ? "opacity-100" : "opacity-0")} />
                  {o.label}
                </Command.Item>
              ))}
            </Command.List>
          </Command>
        </P.Content>
      </P.Portal>
    </P.Root>
  );
}
