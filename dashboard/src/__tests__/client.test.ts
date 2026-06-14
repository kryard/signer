import { describe, expect, it } from "vitest";
import { ApiError, DevAdminClient, type FetchLike } from "@/lib/client";

interface Recorded {
  url: string;
  method?: string;
  body?: string;
  headers?: Record<string, string>;
}

function mockFetch(response: unknown = {}, status = 200) {
  const calls: Recorded[] = [];
  const fetchFn: FetchLike = (url, init) => {
    calls.push({
      url,
      method: init?.method,
      body: typeof init?.body === "string" ? init.body : undefined,
      headers: init?.headers as Record<string, string> | undefined,
    });
    return Promise.resolve(
      new Response(JSON.stringify(response), {
        status,
        headers: { "content-type": "application/json" },
      }),
    );
  };
  return { calls, fetchFn };
}

describe("DevAdminClient URL construction", () => {
  it("lists orgs via GET /api/admin/dev/orgs", async () => {
    const { calls, fetchFn } = mockFetch({ orgs: [{ organizationId: "o1", name: "acme" }] });
    const client = new DevAdminClient(fetchFn);
    const orgs = await client.listOrgs();
    expect(calls[0]).toMatchObject({ url: "/api/admin/dev/orgs", method: "GET" });
    expect(orgs).toEqual([{ id: "o1", name: "acme", createdAt: undefined }]);
  });

  it("creates an org via POST /api/admin/dev/org with a JSON name body", async () => {
    const { calls, fetchFn } = mockFetch({ organizationId: "o1", actorId: "a1" });
    const client = new DevAdminClient(fetchFn);
    const created = await client.createOrg("acme");
    expect(calls[0]).toMatchObject({ url: "/api/admin/dev/org", method: "POST" });
    expect(JSON.parse(calls[0]!.body!)).toEqual({ name: "acme" });
    expect(created.organizationId).toBe("o1");
    expect(created.actorId).toBe("a1");
  });

  it("passes the limit query param when listing activities", async () => {
    const { calls, fetchFn } = mockFetch({ activities: [] });
    const client = new DevAdminClient(fetchFn);
    await client.listActivities("org-1", 25);
    expect(calls[0]!.url).toBe("/api/admin/dev/orgs/org-1/activities?limit=25");
  });

  it("omits the limit query param when not given", async () => {
    const { calls, fetchFn } = mockFetch({ activities: [] });
    const client = new DevAdminClient(fetchFn);
    await client.listActivities("org-1");
    expect(calls[0]!.url).toBe("/api/admin/dev/orgs/org-1/activities");
  });

  it("deletes policy entities with organizationId as a query param", async () => {
    const { calls, fetchFn } = mockFetch({ ok: true });
    const client = new DevAdminClient(fetchFn);
    await client.deleteRule("org-1", "rule-9");
    await client.deleteDestination("org-1", "dest-9");
    await client.deleteBinding("org-1", "bind-9");
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "DELETE /api/admin/dev/policy/rule/rule-9?organizationId=org-1",
      "DELETE /api/admin/dev/policy/destination/dest-9?organizationId=org-1",
      "DELETE /api/admin/dev/policy/binding/bind-9?organizationId=org-1",
    ]);
  });

  it("disables an API key via POST /api-key/:id/disable", async () => {
    const { calls, fetchFn } = mockFetch({ ok: true });
    const client = new DevAdminClient(fetchFn);
    await client.disableApiKey("org-1", "key-7");
    expect(calls[0]).toMatchObject({
      url: "/api/admin/dev/api-key/key-7/disable",
      method: "POST",
    });
    expect(JSON.parse(calls[0]!.body!)).toEqual({ organizationId: "org-1" });
  });

  it("URL-encodes path segments", async () => {
    const { calls, fetchFn } = mockFetch({ activity: {} });
    const client = new DevAdminClient(fetchFn);
    await client.getActivity("org/1", "act 2");
    expect(calls[0]!.url).toBe("/api/admin/dev/orgs/org%2F1/activities/act%202");
  });

  it("normalizes wallet addresses from JSON-stringified arrays", async () => {
    const { fetchFn } = mockFetch({
      wallets: [{ privateKeyId: "pk1", addresses: '["0xabc"]', curve: "CURVE_SECP256K1" }],
    });
    const client = new DevAdminClient(fetchFn);
    const wallets = await client.listWallets("org-1");
    expect(wallets[0]).toMatchObject({ id: "pk1", addresses: ["0xabc"] });
  });

  it("throws ApiError with the server message on non-2xx", async () => {
    const { fetchFn } = mockFetch({ message: "invalid request" }, 400);
    const client = new DevAdminClient(fetchFn);
    await expect(client.listOrgs()).rejects.toThrowError(ApiError);
    await expect(client.listOrgs()).rejects.toThrow("invalid request");
  });
});
