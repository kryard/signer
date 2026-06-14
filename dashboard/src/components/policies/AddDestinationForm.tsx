import { useState } from "react";
import { client } from "@/lib/client";
import type { Wallet } from "@/lib/types";
import { getErrorMessage, truncateMiddle } from "@/lib/format";
import { Button } from "@/components/ui/Button";
import { Field, SelectField } from "@/components/ui/Field";
import { ErrorNote } from "@/components/ui/Feedback";

interface AddDestinationFormProps {
  orgId: string;
  wallets: Wallet[];
  onAdded: () => void;
}

/** Appends a single address to a wallet's per-chain destination allowlist. */
export function AddDestinationForm({ orgId, wallets, onAdded }: AddDestinationFormProps) {
  const [privateKeyId, setPrivateKeyId] = useState("");
  const [chainId, setChainId] = useState("1");
  const [address, setAddress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = Boolean(privateKeyId && chainId.trim() && address.trim());

  const submit = async () => {
    if (!canSubmit || busy) return;
    setBusy(true);
    setError(null);
    try {
      await client.addDestination({
        organizationId: orgId,
        privateKeyId,
        chainId: chainId.trim(),
        address: address.trim(),
      });
      setAddress("");
      onAdded();
    } catch (err: unknown) {
      setError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 items-end gap-3 sm:grid-cols-[1fr_6rem_2fr_auto]">
        <SelectField
          label="Wallet"
          value={privateKeyId}
          onChange={setPrivateKeyId}
          placeholder="Select wallet…"
          options={wallets.map((w) => ({
            value: w.id,
            label: w.name ?? truncateMiddle(w.id),
          }))}
        />
        <Field label="Chain" value={chainId} onChange={setChainId} mono />
        <Field label="Address" value={address} onChange={setAddress} placeholder="0x…" mono />
        <Button onClick={() => void submit()} disabled={!canSubmit || busy}>
          {busy ? "Adding…" : "Add"}
        </Button>
      </div>
      {error && <ErrorNote message={error} />}
    </div>
  );
}
