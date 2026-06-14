import { cn } from "@/lib/cn";
import { CopyButton } from "./CopyButton";

/** Pretty-printed JSON pane for intents / results / receipts. */
export function JsonViewer({
  value,
  className,
  maxHeight = "24rem",
}: {
  value: unknown;
  className?: string;
  maxHeight?: string;
}) {
  const text =
    typeof value === "string" ? value : JSON.stringify(value ?? null, null, 2);
  return (
    <div className={cn("relative rounded-lg border border-line bg-ink", className)}>
      <div className="absolute right-2 top-2">
        <CopyButton value={text} />
      </div>
      <pre
        className="overflow-auto p-4 font-mono text-xs leading-relaxed text-paper/85"
        style={{ maxHeight }}
      >
        {text}
      </pre>
    </div>
  );
}
