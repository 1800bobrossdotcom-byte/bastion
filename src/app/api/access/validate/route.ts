import { NextResponse } from "next/server";
import { validateLicenseKey } from "@/lib/license";

type Body = {
  key?: string;
};

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as Body;
  const key = String(body.key || "").trim();

  if (!key) {
    return NextResponse.json({ ok: false, message: "key required" }, { status: 400 });
  }

  const result = validateLicenseKey(key);

  if (!result.ok) {
    return NextResponse.json({ ok: false, message: result.message || "invalid key" }, { status: 401 });
  }

  return NextResponse.json({ ok: true, payload: result.payload });
}
