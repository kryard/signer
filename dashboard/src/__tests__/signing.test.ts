import { describe, expect, it } from "vitest";
import { parseTransaction, type Hex } from "viem";
import { buildSignTransactionBody, buildUnsignedTx, DEFAULT_TX } from "@/lib/signing";

describe("signing playground pipeline", () => {
  it("serializes the default EIP-1559 transaction like the old dashboard", () => {
    const unsigned = buildUnsignedTx(DEFAULT_TX);
    expect(unsigned.startsWith("0x02")).toBe(true); // EIP-1559 type
    const parsed = parseTransaction(unsigned as Hex);
    expect(parsed).toMatchObject({
      chainId: 1,
      nonce: 0,
      to: DEFAULT_TX.to,
      data: DEFAULT_TX.data,
      gas: 100000n,
      maxFeePerGas: 30000000000n,
      maxPriorityFeePerGas: 1000000000n,
    });
    // viem omits zero-value fields when parsing (value 0 → empty RLP item).
    expect(parsed.value ?? 0n).toBe(0n);
  });

  it("builds a sign_transaction body with the Turnkey activity shape", () => {
    const raw = buildSignTransactionBody("org-1", "pk-1", "0x02deadbeef");
    const body = JSON.parse(raw) as Record<string, unknown>;
    expect(body.type).toBe("ACTIVITY_TYPE_SIGN_TRANSACTION_V2");
    expect(body.organizationId).toBe("org-1");
    expect(typeof body.timestampMs).toBe("string");
    expect(body.parameters).toEqual({
      signWith: "pk-1",
      unsignedTransaction: "0x02deadbeef",
      type: "TRANSACTION_TYPE_ETHEREUM",
    });
  });
});
