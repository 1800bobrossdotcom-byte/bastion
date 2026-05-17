"use client";

import { useState } from "react";

type RequestResult = {
  ok: boolean;
  message?: string;
  key?: string; // dev mode only
};

const BTC_ADDRESS = "bc1qtf6fqllw7dny832ksw67p4a99txgvrct7u9e7d";
const ETH_ADDRESS = "0x70B666c4e3EE5B2C9Ab92925F097330813D1848a";

export default function AccessGateClient() {
  const [email, setEmail] = useState("");
  const [donationUsd, setDonationUsd] = useState("0.00");
  const [status, setStatus] = useState<{ ok?: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    const trimEmail = email.trim();
    const trimAmount = donationUsd.trim() || "0.00";

    if (!trimEmail) {
      setStatus({ ok: false, text: "Email address is required." });
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimEmail)) {
      setStatus({ ok: false, text: "Enter a valid email address." });
      return;
    }
    if (!/^\d+(\.\d{1,2})?$/.test(trimAmount) || parseFloat(trimAmount) < 0) {
      setStatus({ ok: false, text: "Donation must be 0.00 or greater." });
      return;
    }

    setBusy(true);
    setStatus(null);

    try {
      const res = await fetch("/api/access/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: trimEmail, donationUsd: trimAmount }),
      });
      const data = (await res.json()) as RequestResult;

      if (!res.ok || !data.ok) {
        setStatus({ ok: false, text: data.message || `Error ${res.status}` });
        return;
      }

      // Dev mode: show key inline
      if (data.key) {
        setStatus({ ok: true, text: `[dev] Key: ${data.key}` });
      } else {
        setStatus({ ok: true, text: data.message || "Access key sent — check your email." });
      }
    } catch (err) {
      setStatus({ ok: false, text: `Request failed: ${String(err)}` });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel-subtle p-5 sm:p-6">
      <div className="text-[11px] tracking-[0.18em] uppercase text-[color:var(--color-ice)] mb-3">
        Get Access
      </div>
      <p className="text-xs text-[color:var(--color-ice-dim)] mb-4 max-w-lg">
        Access is <strong className="text-[color:var(--color-phosphor)]">donation-based</strong> — enter{" "}
        <code className="text-[color:var(--color-phosphor)]">0.00</code> to get your key for free, or any
        USD amount you wish to pledge. We email your signed key immediately.
      </p>

      <div className="grid gap-3 sm:grid-cols-2 max-w-lg">
        <label className="text-xs text-[color:var(--color-ice-dim)] sm:col-span-2">
          Email address <span className="text-[color:var(--color-phosphor)]">*</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full bg-black/40 border border-[color:var(--color-line-soft)] px-3 py-2 outline-none text-[color:var(--color-phosphor)]"
            placeholder="you@domain.com"
            autoComplete="email"
          />
        </label>

        <label className="text-xs text-[color:var(--color-ice-dim)]">
          Donation amount (USD) <span className="text-[color:var(--color-ice-dim)]">— 0.00 = free</span>
          <div className="mt-1 flex items-center">
            <span className="border border-r-0 border-[color:var(--color-line-soft)] px-2 py-2 text-[color:var(--color-ice-dim)] text-xs bg-black/30">$</span>
            <input
              type="text"
              inputMode="decimal"
              value={donationUsd}
              onChange={(e) => setDonationUsd(e.target.value)}
              className="flex-1 bg-black/40 border border-[color:var(--color-line-soft)] px-3 py-2 outline-none text-[color:var(--color-phosphor)]"
              placeholder="0.00"
            />
          </div>
        </label>
      </div>

      <button
        onClick={submit}
        disabled={busy}
        className="mt-4 btn-primary disabled:opacity-50"
      >
        {busy ? "Sending..." : "Get Access Key"}
      </button>

      {status && (
        <div
          className="mt-3 text-xs"
          style={{ color: status.ok ? "var(--color-phosphor)" : "var(--color-amber)" }}
        >
          {status.text}
        </div>
      )}

      {/* Optional BTC/ETH donation addresses — display only */}
      <div className="mt-6 border-t border-[color:var(--color-line)] pt-4">
        <div className="text-[10px] tracking-[0.16em] uppercase text-[color:var(--color-ice-dim)] mb-2">
          Optional — send BTC or ETH donation
        </div>
        <div className="space-y-2 text-[11px]">
          <div className="flex items-baseline gap-2 flex-wrap">
            <span className="text-[color:var(--color-ice-dim)]">BTC</span>
            <code className="text-[color:var(--color-phosphor)] break-all">{BTC_ADDRESS}</code>
          </div>
          <div className="flex items-baseline gap-2 flex-wrap">
            <span className="text-[color:var(--color-ice-dim)]">ETH</span>
            <code className="text-[color:var(--color-phosphor)] break-all">{ETH_ADDRESS}</code>
          </div>
        </div>
        <p className="text-[10px] text-[color:var(--color-ice-dim)] mt-2">
          Any amount keeps development moving. Paste your email above and submit — your key is emailed regardless.
        </p>
      </div>
    </div>
  );
}

