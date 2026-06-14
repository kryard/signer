import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/cn";

/** Copy-to-clipboard icon button with a brief confirmation tick. */
export function CopyButton({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard
      .writeText(value)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      })
      .catch(() => {
        // Clipboard unavailable (permissions / insecure context) — ignore.
      });
  };

  return (
    <button
      type="button"
      onClick={copy}
      title="Copy"
      aria-label="Copy to clipboard"
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded p-1 text-mist transition-colors hover:text-signal",
        className,
      )}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-signal" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

/** A truncated mono value with copy affordance, for ids/hashes/addresses. */
export function MonoCopy({
  value,
  display,
  className,
}: {
  value: string;
  display?: string;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-xs", className)}>
      <span className="break-all">{display ?? value}</span>
      <CopyButton value={value} />
    </span>
  );
}
