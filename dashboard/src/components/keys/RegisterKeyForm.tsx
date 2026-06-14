import { useState } from "react";
import { client } from "@/lib/client";
import type { Actor } from "@/lib/types";
import { generateIdentity, saveIdentity, SCHEME_P256 } from "@/lib/stamp";
import { getErrorMessage } from "@/lib/format";
import { Button } from "@/components/ui/Button";
import { Field, SelectField } from "@/components/ui/Field";
import { MonoCopy } from "@/components/ui/CopyButton";
import { ErrorNote } from "@/components/ui/Feedback";

interface RegisterKeyFormProps {
  orgId: string;
  actors: Actor[];
  onRegistered: () => void;
}

/**
 * Register a P-256 stamp public key as an API key. Either paste an existing
 * compressed public key, or generate a keypair in the browser — the private
 * key is displayed ONCE and can optionally become this browser's signing
 * identity (used by the Sign playground).
 */
export function RegisterKeyForm({ orgId, actors, onRegistered }: RegisterKeyFormProps) {
  const [actorId, setActorId] = useState(actors[0]?.id ?? "");
  const [name, setName] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [generatedPriv, setGeneratedPriv] = useState<string | null>(null);
  const [useAsConsoleIdentity, setUseAsConsoleIdentity] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const effectiveActorId = actorId || actors[0]?.id || "";

  const generate = () => {
    const identity = generateIdentity();
    setPublicKey(identity.publicKeyHex);
    setGeneratedPriv(identity.privateKeyHex);
  };

  const downloadPriv = () => {
    if (!generatedPriv) return;
    const blob = new Blob([generatedPriv], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "kryard-p256-private-key.hex";
    a.click();
    URL.revokeObjectURL(url);
  };

  const submit = async () => {
    if (!publicKey.trim() || !effectiveActorId || busy) return;
    setBusy(true);
    setError(null);
    try {
      await client.registerApiKey({
        organizationId: orgId,
        actorId: effectiveActorId,
        publicKey: publicKey.trim().toLowerCase(),
        scheme: SCHEME_P256,
        name: name.trim() || undefined,
      });
      if (generatedPriv && useAsConsoleIdentity) {
        saveIdentity({ privateKeyHex: generatedPriv, publicKeyHex: publicKey.trim().toLowerCase() });
      }
      setName("");
      setPublicKey("");
      setGeneratedPriv(null);
      onRegistered();
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
          label="Actor"
          value={effectiveActorId}
          onChange={setActorId}
          options={actors.map((a) => ({ value: a.id, label: a.name }))}
        />
        <Field label="Name (optional)" value={name} onChange={setName} placeholder="ci-relayer-key" />
      </div>

      <div className="flex items-end gap-3">
        <Field
          label="Compressed P-256 public key (hex)"
          value={publicKey}
          onChange={(v) => {
            setPublicKey(v);
            setGeneratedPriv(null); // pasted key replaces the generated one
          }}
          placeholder="02ab…"
          mono
          className="flex-1"
        />
        <Button variant="ghost" onClick={generate}>
          Generate in browser
        </Button>
      </div>

      {generatedPriv && (
        <div className="space-y-3 rounded-lg border border-amber/40 bg-amber/10 p-4">
          <p className="text-sm font-medium text-amber">
            Private key — shown once, never sent to the server. Copy or download it now.
          </p>
          <MonoCopy value={generatedPriv} className="break-all text-paper/90" />
          <div className="flex flex-wrap items-center gap-4">
            <Button size="sm" variant="ghost" onClick={downloadPriv}>
              Download .hex
            </Button>
            <label className="flex items-center gap-2 text-xs text-paper/80">
              <input
                type="checkbox"
                checked={useAsConsoleIdentity}
                onChange={(e) => setUseAsConsoleIdentity(e.target.checked)}
                className="accent-[var(--color-signal)]"
              />
              Use as this browser's signing identity (Sign playground)
            </label>
          </div>
        </div>
      )}

      {error && <ErrorNote message={error} />}

      <Button onClick={() => void submit()} disabled={busy || !publicKey.trim() || !effectiveActorId}>
        {busy ? "Registering…" : "Register API key"}
      </Button>
    </div>
  );
}
