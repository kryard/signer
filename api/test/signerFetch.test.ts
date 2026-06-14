/**
 * Unit tests for the SignerFetch transport abstraction.
 *
 * Verifies that:
 * - sigv4Fetch produces requests with AWS4-HMAC-SHA256 Authorization and x-amz-date headers
 * - plainFetch does NOT add those headers
 *
 * No network I/O — fetch is mocked via vitest.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { plainFetch, sigv4Fetch } from "../src/signerClient";

// Fixed test credentials — never used against real AWS.
const TEST_CREDS = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  region: "ap-northeast-2",
};

const TEST_URL = "https://abc123.lambda-url.ap-northeast-2.on.aws/internal/health";
const TEST_INIT: RequestInit = {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ ping: true }),
};

describe("plainFetch", () => {
  let capturedRequest: Request | null = null;

  beforeEach(() => {
    capturedRequest = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
        // Capture what was passed to fetch so we can inspect headers.
        capturedRequest = new Request(input as string, _init);
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("does NOT add Authorization or x-amz-date headers", async () => {
    await plainFetch(TEST_URL, TEST_INIT);
    expect(capturedRequest).not.toBeNull();
    const auth = capturedRequest!.headers.get("authorization");
    const date = capturedRequest!.headers.get("x-amz-date");
    expect(auth).toBeNull();
    expect(date).toBeNull();
  });
});

describe("sigv4Fetch", () => {
  let capturedRequest: Request | null = null;

  beforeEach(() => {
    capturedRequest = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
        // aws4fetch passes a pre-signed Request object as the first argument.
        if (input instanceof Request) {
          capturedRequest = input;
        } else {
          capturedRequest = new Request(input as string, _init);
        }
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("adds Authorization: AWS4-HMAC-SHA256 header", async () => {
    const fetch = sigv4Fetch(TEST_CREDS);
    await fetch(TEST_URL, TEST_INIT);
    expect(capturedRequest).not.toBeNull();
    const auth = capturedRequest!.headers.get("authorization");
    expect(auth).not.toBeNull();
    expect(auth).toMatch(/^AWS4-HMAC-SHA256 /);
  });

  it("adds x-amz-date header", async () => {
    const fetch = sigv4Fetch(TEST_CREDS);
    await fetch(TEST_URL, TEST_INIT);
    expect(capturedRequest).not.toBeNull();
    const date = capturedRequest!.headers.get("x-amz-date");
    expect(date).not.toBeNull();
    // x-amz-date format: YYYYMMDDTHHmmssZ
    expect(date).toMatch(/^\d{8}T\d{6}Z$/);
  });

  it("signs with the correct AWS access key ID in the Credential scope", async () => {
    const fetch = sigv4Fetch(TEST_CREDS);
    await fetch(TEST_URL, TEST_INIT);
    const auth = capturedRequest!.headers.get("authorization") ?? "";
    expect(auth).toContain(TEST_CREDS.accessKeyId);
  });
});
