import crypto from "node:crypto";

export type AccessPayload = {
  email: string;
  donationUsd: number;
  issuedAt: number;
};

function secret(): string {
  return process.env.BASTION_LICENSE_SECRET || "dev-insecure-secret-change-me";
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64url(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
}

export function createLicenseKey(payload: AccessPayload): string {
  const packed = base64url(JSON.stringify(payload));
  const sig = base64url(
    crypto.createHmac("sha256", secret()).update(packed).digest().subarray(0, 18)
  );
  return `BSTN.${packed}.${sig}`;
}

export function validateLicenseKey(key: string): { ok: boolean; payload?: AccessPayload; message?: string } {
  // Strip ALL whitespace (newlines, spaces, tabs) defensively — emails wrap
  // long keys across lines and users sometimes paste with a stray newline.
  const cleaned = key.replace(/\s+/g, "");
  const [prefix, packed, sig] = cleaned.split(".");

  if (prefix !== "BSTN" || !packed || !sig) {
    return { ok: false, message: "invalid key format" };
  }

  const expected = base64url(
    crypto.createHmac("sha256", secret()).update(packed).digest().subarray(0, 18)
  );

  if (expected !== sig) {
    return { ok: false, message: "signature mismatch" };
  }

  try {
    const payload = JSON.parse(fromBase64url(packed).toString("utf8")) as AccessPayload;
    if (!payload?.email) {
      return { ok: false, message: "payload incomplete" };
    }
    return { ok: true, payload };
  } catch {
    return { ok: false, message: "payload decode failed" };
  }
}

export function createIntentId(): string {
  return crypto.randomBytes(8).toString("hex");
}
