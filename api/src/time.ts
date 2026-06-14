import type { ProtoTimestamp } from "./types";

/** Convert a JS Date to Turnkey's {seconds,nanos} protobuf timestamp. */
export function toProtoTimestamp(date: Date): ProtoTimestamp {
  const ms = date.getTime();
  const seconds = Math.floor(ms / 1000);
  const nanos = (ms % 1000) * 1_000_000;
  return { seconds: String(seconds), nanos: String(nanos) };
}
