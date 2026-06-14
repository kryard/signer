import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // Integration tests start a Postgres container; give them room.
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
