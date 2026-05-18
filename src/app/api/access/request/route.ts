import { NextResponse } from "next/server";
import { Resend } from "resend";
import { createLicenseKey } from "@/lib/license";
import { insertAccessRequest } from "@/lib/supabase-server";
import crypto from "node:crypto";

type Body = {
  email?: string;
  donationUsd?: string;
};

function validEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as Body;
  const email = String(body.email || "").trim().toLowerCase();
  const rawAmount = String(body.donationUsd || "0.00").trim();

  if (!validEmail(email)) {
    return NextResponse.json({ ok: false, message: "A valid email address is required." }, { status: 400 });
  }

  if (!/^\d+(\.\d{1,2})?$/.test(rawAmount)) {
    return NextResponse.json({ ok: false, message: "Donation amount must be a number (e.g. 0.00)." }, { status: 400 });
  }

  const donationUsd = parseFloat(rawAmount);
  if (!Number.isFinite(donationUsd) || donationUsd < 0) {
    return NextResponse.json({ ok: false, message: "Donation amount must be 0.00 or greater." }, { status: 400 });
  }

  // Issue key immediately — honor-based donation model
  const key = createLicenseKey({ email, donationUsd, issuedAt: Date.now() });

  // Store in Supabase (non-fatal if not configured)
  const keyHash = crypto.createHash("sha256").update(key).digest("hex");
  await insertAccessRequest({ email, donation_usd: donationUsd, key_hash: keyHash });

  // Send key by email via Resend
  const resendKey = process.env.RESEND_API_KEY;
  if (!resendKey) {
    // Dev: return key in body so you can test without email configured
    return NextResponse.json({ ok: true, key, message: "[dev] RESEND_API_KEY not set — key in response." });
  }

  const fromEmail = process.env.BASTION_FROM_EMAIL || "access@bastion.quest";
  const resend = new Resend(resendKey);

  const { error } = await resend.emails.send({
    from: fromEmail,
    to: email,
    subject: "Your Bastion Access Key",
    html: `
      <div style="background:#0a0a0a;color:#e0e0e0;font-family:monospace;padding:32px;max-width:520px;margin:auto;border:1px solid #222;">
        <div style="color:#00ff66;font-size:11px;letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">
          BASTION // ACCESS KEY
        </div>
        <p style="color:#aaa;font-size:14px;margin-bottom:24px;">
          Here is your Bastion console access key. Paste it at
          <a href="https://bastion.quest/app" style="color:#8ee8ff;">bastion.quest/app</a>.
        </p>
        <div style="background:#111;border:1px solid #2a2a2a;padding:16px;word-break:break-all;color:#00ff66;font-size:13px;letter-spacing:0.04em;user-select:all;">
          ${key}
        </div>
        <p style="color:#888;font-size:11px;margin-top:12px;">
          Tip: triple-click the key above to select it cleanly. The key is case-sensitive — do not modify it.
        </p>
        <p style="color:#555;font-size:11px;margin-top:24px;">
          If you pledged a donation, please send BTC or ETH to the addresses on bastion.quest — any amount is appreciated.<br/>
          Thank you for supporting open-source defensive tools.
        </p>
      </div>
    `,
  });

  if (error) {
    console.error("[access/request] resend error:", error);
    return NextResponse.json(
      { ok: false, message: "Key generated but email failed. Contact support@bastion.quest." },
      { status: 500 }
    );
  }

  return NextResponse.json({ ok: true, message: "Access key sent — check your email." });
}
