import { describe, it, expect } from "vitest";
import { createApp } from "../src/app";

describe("health", () => {
  it("returns ok without touching the db", async () => {
    const app = createApp({ db: {} as never, signerBaseUrl: "http://localhost:9999" });
    const res = await app.request("/internal/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });
});
