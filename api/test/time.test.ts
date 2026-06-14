import { describe, it, expect } from "vitest";
import { toProtoTimestamp } from "../src/time";

describe("toProtoTimestamp", () => {
  it("splits ms into seconds and nanos", () => {
    expect(toProtoTimestamp(new Date(1780422786123))).toEqual({
      seconds: "1780422786",
      nanos: "123000000",
    });
  });
});
