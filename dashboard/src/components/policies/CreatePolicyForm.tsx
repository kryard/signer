import { useState } from "react";
import { client } from "@/lib/client";
import type { Actor, Wallet } from "@/lib/types";
import { getErrorMessage, truncateMiddle } from "@/lib/format";
import { Button } from "@/components/ui/Button";
import { Field, SelectField } from "@/components/ui/Field";
import { ErrorNote } from "@/components/ui/Feedback";

interface CreatePolicyFormProps {
  orgId: string;
  wallets: Wallet[];
  actors: Actor[];
  onCreated: () => void;
}

/**
 * Seeds a full policy (binding + per-chain rule + destination allowlist entry)
 * for one wallet via POST /admin/dev/policy.
 */
export function CreatePolicyForm({ orgId, wallets, actors, onCreated }: CreatePolicyFormProps) {
  const [privateKeyId, setPrivateKeyId] = useState("");
  const [actorId, setActorId] = useState(actors[0]?.id ?? "");
  const [chainId, setChainId] = useState("1");
  const [methodSelector, setMethodSelector] = useState("0x7fea8778");
  const [destinationAddress, setDestinationAddress] = useState("");
  const [maxNativeValueWei, setMaxNativeValueWei] = useState("0");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const effectiveActorId = actorId || actors[0]?.id || "";
  const canSubmit =
    Boolean(privateKeyId && effectiveActorId && chainId.trim() && methodSelector.trim() && destinationAddress.trim());

  const submit = async () => {
    if (!canSubmit || busy) return;
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      await client.seedPolicy({
        organizationId: orgId,
        actorId: effectiveActorId,
        privateKeyId,
        chainId: chainId.trim(),
        methodSelector: methodSelector.trim(),
        destinationAddress: destinationAddress.trim(),
        maxNativeValueWei: maxNativeValueWei.trim() || "0",
      });
      setDone(true);
      onCreated();
    } catch (err: unknown) {
      setError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <SelectField
          label="Wallet"
          value={privateKeyId}
          onChange={setPrivateKeyId}
          placeholder="Select wallet…"
          options={wallets.map((w) => ({
            value: w.id,
            label: `${w.name ?? truncateMiddle(w.id)} · ${truncateMiddle(w.addresses[0] ?? "", 8, 6)}`,
          }))}
        />
        <SelectField
          label="Actor"
          value={effectiveActorId}
          onChange={setActorId}
          options={actors.map((a) => ({ value: a.id, label: a.name }))}
        />
        <Field label="Chain ID" value={chainId} onChange={setChainId} mono />
        <Field label="Method selector" value={methodSelector} onChange={setMethodSelector} mono />
        <Field
          label="Destination address"
          value={destinationAddress}
          onChange={setDestinationAddress}
          placeholder="0x…"
          mono
          className="sm:col-span-2"
        />
        <Field
          label="Max native value (wei)"
          value={maxNativeValueWei}
          onChange={setMaxNativeValueWei}
          mono
        />
      </div>
      {error && <ErrorNote message={error} />}
      {done && !error && (
        <p className="text-sm text-signal">Policy seeded — binding, rule, and destination created.</p>
      )}
      <Button onClick={() => void submit()} disabled={!canSubmit || busy}>
        {busy ? "Seeding…" : "Seed policy"}
      </Button>
    </div>
  );
}
