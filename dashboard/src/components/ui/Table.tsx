import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/** Console table primitives — consistent hairline rows + mono-friendly cells. */

export function Table({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  );
}

export function THead({ columns }: { columns: string[] }) {
  return (
    <thead>
      <tr className="border-b border-line">
        {columns.map((col) => (
          <th key={col} className="eyebrow px-3 py-2.5 text-left font-medium text-mist">
            {col}
          </th>
        ))}
      </tr>
    </thead>
  );
}

export function TBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-line/60">{children}</tbody>;
}

export function Tr({
  children,
  onClick,
  className,
}: {
  children: ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        "transition-colors duration-150",
        onClick && "cursor-pointer hover:bg-ink-3/70",
        className,
      )}
    >
      {children}
    </tr>
  );
}

export function Td({
  children,
  mono,
  className,
}: {
  children: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <td className={cn("px-3 py-3 align-middle", mono && "font-mono text-xs", className)}>
      {children}
    </td>
  );
}
