import { useState } from "react";
import { client } from "@/lib/client";
import { generateIdentity, saveIdentity, SCHEME_P256, type StampIdentity } from "@/lib/stamp";
import { getErrorMessage } from "@/lib/format";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { MonoCopy } from "@/components/ui/CopyButton";
import { ErrorNote } from "@/components/ui/Feedback";

interface IdentityCardProps {
  orgId: string;
  actorId?: string;
  identity: StampIdentity | null;
  onIdentityChange: (identity: StampIdentity) => void;
}

/**
 * The browser's P-256 signing identity. Generated client-side, persisted in
 * localStorage; its public half must be registered as an API key before the
 * playground can X-Stamp requests.
 */
export function IdentityCard({ orgId, actorId, identity, onIdentityChange }: IdentityCardProps) {
  const [busy, setBusy] = useState(false);
  const [registered, setRegistered] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = () => {
    if (
      identity &&
      !window.confirm("Replace the stored identity? Keys registered for the old one stop working.")
    ) {
      return;
    }
    const next = generateIdentity();
    saveIdentity(next);
    setRegistered(false);
    onIdentityChange(next);
  };

  const register = async () => {
    if (!identity || !actorId || busy) return;
    setBusy(true);
    setError(null);
    try {
      await client.registerApiKey({
        organizationId: orgId,
        actorId,
        publicKey: identity.publicKeyHex,
        scheme: SCHEME_P256,
        name: "console-playground-key",
      });
      setRegistered(true);
    } catch (err: unknown) {
      setError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Browser P-256 identity">
      <div className="space-y-3">
        {identity ? (
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="eyebrow w-28 shrink-0 text-mist">Public key</span>
            <MonoCopy value={identity.publicKeyHex} />
          </div>
        ) : (
          <p className="text-sm text-mist-2">
            No identity in this browser yet. Generate one — the private key never leaves
            localStorage.
          </p>
        )}
        {error && <ErrorNote message={error} />}
        {registered && (
          <p className="text-sm text-signal">Public key registered as an API key for this org.</p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button variant="ghost" size="sm" onClick={generate}>
            {identity ? "Regenerate identity" : "Generate identity"}
          </Button>
          {identity && (
            <Button size="sm" onClick={() => void register()} disabled={busy || !actorId}>
              {busy ? "Registering…" : "Register as API key"}
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}
