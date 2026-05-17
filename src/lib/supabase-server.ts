import { createClient } from "@supabase/supabase-js";

export type AccessRequest = {
  id?: string;
  email: string;
  donation_usd: number;
  key_hash: string;
  created_at?: string;
};

function getClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (!url || !key) return null;
  return createClient(url, key, { auth: { persistSession: false } });
}

export async function insertAccessRequest(record: Omit<AccessRequest, "id" | "created_at">): Promise<{ ok: boolean; message?: string }> {
  const client = getClient();
  if (!client) return { ok: false, message: "supabase not configured" };

  const { error } = await client.from("access_requests").insert(record);
  if (error) return { ok: false, message: error.message };
  return { ok: true };
}
