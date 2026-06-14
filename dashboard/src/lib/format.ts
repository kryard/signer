/** Small presentation helpers shared across pages. */

/** Truncate a long id/hash/address for table display: 0x1234…abcd */
export function truncateMiddle(value: string, head = 8, tail = 6): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Human-readable timestamp (local time) from an ISO string. */
export function formatTime(iso?: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Strip the ACTIVITY_TYPE_ prefix for friendlier table cells. */
export function formatActivityType(type: string): string {
  return type.replace(/^ACTIVITY_TYPE_/, "");
}

export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Unexpected error";
}
