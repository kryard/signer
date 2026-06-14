import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { canonicalize, sha256Hex } from "../src/canonicalJson";

describe("canonicalize", () => {
  it("sorts keys recursively, preserves array order", () => {
    expect(canonicalize({ z: [{ b: 1, a: 2 }], a: 3 })).toBe('{"a":3,"z":[{"a":2,"b":1}]}');
  });
});

describe("sha256Hex (async, WebCrypto)", () => {
  it("matches known NIST vectors", async () => {
    expect(await sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  // Lock against a real P0-captured request body if the local fixtures exist.
  it("hashes a real captured sign_transaction body deterministically", async () => {
    const p = "../../tools/compat-harness/fixtures/exchanges.json";
    if (!existsSync(p)) return; // fixtures are gitignored; skip when absent
    const exchanges = JSON.parse(readFileSync(p, "utf8")) as { requestBody?: string }[];
    const body = exchanges.find((e) => e.requestBody)?.requestBody;
    if (!body) return;
    const h1 = await sha256Hex(canonicalize(JSON.parse(body)));
    const h2 = await sha256Hex(canonicalize(JSON.parse(body)));
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });
});
