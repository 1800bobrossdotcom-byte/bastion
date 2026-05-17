import { NextResponse } from "next/server";

// This route is a legacy internal endpoint, kept for manual key issuance if needed.
// The primary flow is now: /api/access/request issues keys automatically.

export async function POST(req: Request) {
  const expectedSecret = process.env.BASTION_CONFIRM_SECRET;
  const provided = req.headers.get("x-bastion-confirm-secret") || "";

  if (!expectedSecret || provided !== expectedSecret) {
    return NextResponse.json({ ok: false, message: "unauthorized" }, { status: 401 });
  }

  void req; // unused after auth check
  return NextResponse.json({ ok: true, message: "Keys are now issued automatically via /api/access/request." });
}

