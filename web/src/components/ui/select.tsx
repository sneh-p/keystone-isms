import * as S from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

export type Option = { value: string; label: string };
const NONE = "__none__";

/** Accessible select. `value` null/"" maps to the optional empty option. */
export function Select({ value, onChange, options, placeholder = "Select…", allowEmpty, emptyLabel = "—", className, disabled, ariaLabel }: {
  value: string | null | undefined;
  onChange: (v: string | null) => void;
  options: Option[];
  placeholder?: string;
  allowEmpty?: boolean;
  emptyLabel?: string;
  className?: string;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  return (
    <S.Root value={value ? String(value) : allowEmpty ? NONE : undefined} onValueChange={(v) => onChange(v === NONE ? null : v)} disabled={disabled}>
      <S.Trigger aria-label={ariaLabel} className={cn("flex h-9 w-full items-center justify-between gap-2 rounded-md border border-input bg-card px-3 text-sm shadow-card transition-[border-color,box-shadow] hover:border-foreground/25 focus:border-ring focus:outline-none focus:ring-[3px] focus:ring-ring/20 disabled:opacity-50 data-[placeholder]:text-muted-foreground", className)}>
        <span className="min-w-0 flex-1 truncate text-left">
          <S.Value placeholder={placeholder} />
        </span>
        <S.Icon>
          <ChevronDown className="size-4 opacity-60" />
        </S.Icon>
      </S.Trigger>
      <S.Portal>
        <S.Content position="popper" sideOffset={4} className="z-50 max-h-80 min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-lg border bg-popover text-popover-foreground shadow-pop animate-fade-in">
          <S.Viewport className="p-1">
            {allowEmpty && <Item value={NONE} label={emptyLabel} />}
            {options.map((o) => (
              <Item key={o.value} value={o.value} label={o.label} />
            ))}
          </S.Viewport>
        </S.Content>
      </S.Portal>
    </S.Root>
  );
}

function Item({ value, label }: Option) {
  return (
    <S.Item value={value} className="relative flex cursor-pointer select-none items-center rounded-md py-1.5 pl-7 pr-2 text-sm outline-none data-[highlighted]:bg-muted data-[state=checked]:font-medium">
      <S.ItemIndicator className="absolute left-2">
        <Check className="size-3.5 text-primary" />
      </S.ItemIndicator>
      <S.ItemText>{label}</S.ItemText>
    </S.Item>
  );
}
