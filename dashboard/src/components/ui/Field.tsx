import type { ChangeEvent } from "react";
import { cn } from "@/lib/cn";

interface FieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  mono?: boolean;
  type?: string;
  className?: string;
}

/** Labeled text input in the console style. */
export function Field({ label, value, onChange, placeholder, mono, type, className }: FieldProps) {
  return (
    <label className={cn("block", className)}>
      <span className="eyebrow mb-1.5 block text-mist">{label}</span>
      <input
        type={type ?? "text"}
        value={value}
        placeholder={placeholder}
        onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
        className={cn("field-input", mono && "font-mono text-xs")}
      />
    </label>
  );
}

interface SelectFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  placeholder?: string;
  className?: string;
}

/** Labeled select in the console style. */
export function SelectField({
  label,
  value,
  onChange,
  options,
  placeholder,
  className,
}: SelectFieldProps) {
  return (
    <label className={cn("block", className)}>
      <span className="eyebrow mb-1.5 block text-mist">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="field-input appearance-none"
      >
        {placeholder && <option value="">{placeholder}</option>}
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </label>
  );
}
