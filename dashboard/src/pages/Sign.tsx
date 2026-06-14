import { useState } from "react";
import { Link } from "react-router-dom";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { loadIdentity, type StampIdentity } from "@/lib/stamp";
import {
  buildSignTransactionBody,
  buildUnsignedTx,
  DEFAULT_TX,
  recoverSigner,
  submitSignTransaction,
  type SignResult,
  type TxFormValues,
} from "@/lib/signing";
import { getErrorMessage, truncateMiddle } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, SelectField } from "@/components/ui/Field";
import { JsonViewer } from "@/components/ui/JsonViewer";
import { MonoCopy } from "@/components/ui/CopyButton";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { ErrorNote, Loading } from "@/components/ui/Feedback";
import { IdentityCard } from "@/components/sign/IdentityCard";

interface PlaygroundResult extends SignResult {
  recoveredAddress?: string;
  expectedAddress?: string;
}

export function Sign() {
  const { selectedOrg } = useOrg();
  const orgId = selectedOrg?.id ?? "";

  const { data, loading, error } = useAsync(async () => {
    const [wallets, org] = await Promise.all([client.listWallets(orgId), client.getOrg(orgId)]);
    return { wallets, actorId: org.actors[0]?.id };
  }, [orgId]);

  const [identity, setIdentity] = useState<StampIdentity | null>(() => loadIdentity());
  const [walletId, setWalletId] = useState("");
  const [tx, setTx] = useState<TxFormValues>(DEFAULT_TX);
  const [busy, setBusy] = useState(false);
  const [signError, setSignError] = useState<string | null>(null);
  const [result, setResult] = useState<PlaygroundResult | null>(null);

  const setTxField = (key: keyof TxFormValues) => (value: string) =>
    setTx((prev) => ({ ...prev, [key]: value }));

  const selectedWallet = data?.wallets.find((w) => w.id === walletId) ?? null;
  const canSign = Boolean(identity && walletId && tx.to.trim());

  const sign = async () => {
    if (!identity || !walletId || busy) return;
    setBusy(true);
    setSignError(null);
    setResult(null);
    try {
      // 1. Build the unsigned EIP-1559 tx (viem RLP serialization).
      const unsigned = buildUnsignedTx(tx);
      // 2. Build the EXACT raw body string, X-Stamp it, and POST that string.
      const rawBody = buildSignTransactionBody(orgId, walletId, unsigned);
      const signResult = await submitSignTransaction(identity, rawBody);
      // 3. Verify locally: recover the signer address from the signed tx.
      let recoveredAddress: string | undefined;
      if (signResult.signedTransaction) {
        recoveredAddress = await recoverSigner(signResult.signedTransaction).catch(() => undefined);
      }
      setResult({
        ...signResult,
        recoveredAddress,
        expectedAddress: selectedWallet?.addresses[0],
      });
    } catch (err: unknown) {
      setSignError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (!selectedOrg) return null;

  const recoveredMatches =
    result?.recoveredAddress &&
    result.expectedAddress &&
    result.recoveredAddress.toLowerCase() === result.expectedAddress.toLowerCase();

  return (
    <>
      <PageHeader
        title="Sign"
        description="Signing playground: build an EIP-1559 transaction, X-Stamp the exact request body in the browser, and submit a real sign_transaction activity."
      />

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}

      {data && (
        <div className="space-y-6">
          <IdentityCard
            orgId={orgId}
            actorId={data.actorId}
            identity={identity}
            onIdentityChange={setIdentity}
          />

          <Card title="Transaction">
            <div className="space-y-4">
              <SelectField
                label="Wallet (signWith)"
                value={walletId}
                onChange={setWalletId}
                placeholder="Select wallet…"
                options={data.wallets.map((w) => ({
                  value: w.id,
                  label: `${w.name ?? truncateMiddle(w.id)} · ${truncateMiddle(w.addresses[0] ?? "", 8, 6)}`,
                }))}
              />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field label="Chain ID" value={tx.chainId} onChange={setTxField("chainId")} mono />
                <Field label="Nonce" value={tx.nonce} onChange={setTxField("nonce")} mono />
                <Field
                  label="To (must be allowlisted)"
                  value={tx.to}
                  onChange={setTxField("to")}
                  mono
                  className="sm:col-span-2"
                />
                <Field
                  label="Data / method selector"
                  value={tx.data}
                  onChange={setTxField("data")}
                  mono
                />
                <Field label="Value (wei)" value={tx.valueWei} onChange={setTxField("valueWei")} mono />
                <Field label="Gas limit" value={tx.gas} onChange={setTxField("gas")} mono />
                <Field
                  label="Max fee per gas (wei)"
                  value={tx.maxFeePerGas}
                  onChange={setTxField("maxFeePerGas")}
                  mono
                />
                <Field
                  label="Max priority fee (wei)"
                  value={tx.maxPriorityFeePerGas}
                  onChange={setTxField("maxPriorityFeePerGas")}
                  mono
                />
              </div>
              {signError && <ErrorNote message={signError} />}
              <Button onClick={() => void sign()} disabled={!canSign || busy}>
                {busy ? "Signing…" : "Build + sign transaction"}
              </Button>
              {!identity && (
                <p className="text-xs text-mist">
                  Generate a browser identity above (and register it as an API key) before signing.
                </p>
              )}
            </div>
          </Card>

          {result && (
            <Card
              title="Result"
              actions={<StatusBadge status={result.status} />}
            >
              <div className="space-y-4">
                {result.activityId && (
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="eyebrow w-32 shrink-0 text-mist">Activity</span>
                    <Link
                      to={`/activities/${result.activityId}`}
                      className="font-mono text-xs text-signal hover:underline"
                    >
                      {result.activityId}
                    </Link>
                  </div>
                )}

                {result.signedTransaction ? (
                  <>
                    <div className="flex flex-wrap items-start gap-2 text-sm">
                      <span className="eyebrow w-32 shrink-0 text-mist">Signed tx</span>
                      <span className="min-w-0 flex-1">
                        <MonoCopy value={result.signedTransaction} />
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <span className="eyebrow w-32 shrink-0 text-mist">Recovered signer</span>
                      {result.recoveredAddress ? (
                        <span className="inline-flex items-center gap-2">
                          <MonoCopy value={result.recoveredAddress} />
                          <StatusBadge
                            status={recoveredMatches ? "COMPLETED" : "FAILED"}
                            className="!px-2"
                          />
                          <span className={recoveredMatches ? "text-signal" : "text-danger"}>
                            {recoveredMatches
                              ? "matches wallet address"
                              : `expected ${result.expectedAddress ?? "?"}`}
                          </span>
                        </span>
                      ) : (
                        <span className="text-mist">could not recover</span>
                      )}
                    </div>
                  </>
                ) : (
                  <ErrorNote message="No signedTransaction in the response — likely a policy denial. Check the activity detail." />
                )}

                <JsonViewer value={result.raw} maxHeight="20rem" />
              </div>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
