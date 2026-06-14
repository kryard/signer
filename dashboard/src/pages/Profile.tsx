import { useState } from "react";
import { Link } from "react-router-dom";
import { useAsync } from "@/lib/useAsync";
import { isLocalMode } from "@/lib/client";
import { ACCESS_LOGOUT_URL, fetchAccessIdentity } from "@/lib/access";
import {
  clearIdentity,
  generateIdentity,
  loadIdentity,
  saveIdentity,
  type StampIdentity,
} from "@/lib/stamp";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { MonoCopy } from "@/components/ui/CopyButton";
import { Loading } from "@/components/ui/Feedback";

export function Profile() {
  const { data: access, loading } = useAsync(() => fetchAccessIdentity(), []);
  const [identity, setIdentity] = useState<StampIdentity | null>(() => loadIdentity());

  const regenerate = () => {
    if (
      identity &&
      !window.confirm("Replace the stored identity? API keys registered for the old one stop working.")
    ) {
      return;
    }
    const next = generateIdentity();
    saveIdentity(next);
    setIdentity(next);
  };

  const clear = () => {
    if (!window.confirm("Remove the signing identity from this browser?")) return;
    clearIdentity();
    setIdentity(null);
  };

  return (
    <>
      <PageHeader
        title="Profile"
        description="Who you are to this console: your SSO login (when deployed) and this browser's signing identity."
      />

      <div className="space-y-6">
        <Card title="Access identity (SSO)">
          {loading ? (
            <Loading />
          ) : access ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="eyebrow w-32 shrink-0 text-mist">Email</span>
                <span className="text-paper">{access.email}</span>
              </div>
              {access.name && (
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="eyebrow w-32 shrink-0 text-mist">Name</span>
                  <span className="text-paper">{access.name}</span>
                </div>
              )}
              {access.idpName && (
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="eyebrow w-32 shrink-0 text-mist">Identity provider</span>
                  <span className="font-mono text-xs text-mist-2">{access.idpName}</span>
                </div>
              )}
              <div className="border-t border-line pt-3">
                <a
                  href={ACCESS_LOGOUT_URL}
                  className="text-sm text-danger underline-offset-4 hover:underline"
                >
                  Sign out of Cloudflare Access
                </a>
              </div>
            </div>
          ) : isLocalMode ? (
            <p className="text-sm text-mist-2">
              Running locally, no auth. Cloudflare Access is not in front of a local API —
              the dashboard talks directly to your local Kryard API with no SSO and no admin
              token. (Access only fronts the deployed console route.)
            </p>
          ) : (
            <p className="text-sm text-mist-2">
              No Cloudflare Access identity — you're likely running locally (Access only fronts
              the deployed console route).
            </p>
          )}
        </Card>

        <Card title="Browser signing identity (P-256 API key)">
          <div className="space-y-3">
            {identity ? (
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="eyebrow w-32 shrink-0 text-mist">Public key</span>
                <MonoCopy value={identity.publicKeyHex} />
              </div>
            ) : (
              <p className="text-sm text-mist-2">
                No signing identity in this browser. Generate one — the private key lives in
                localStorage and never leaves this machine.
              </p>
            )}
            <p className="text-xs text-mist">
              This key X-Stamps your playground requests. Register its public half as an API key
              per organization on the <Link to="/sign" className="text-signal hover:underline">Sign</Link>{" "}
              page (or <Link to="/keys" className="text-signal hover:underline">API keys</Link>).
            </p>
            <div className="flex flex-wrap gap-2">
              <Button variant="ghost" size="sm" onClick={regenerate}>
                {identity ? "Regenerate identity" : "Generate identity"}
              </Button>
              {identity && (
                <Button variant="danger" size="sm" onClick={clear}>
                  Remove from this browser
                </Button>
              )}
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}
