"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

// ---------------------------------------------------------------------------
// Consumer console.  Replaces the old terminal-style operator view, which is
// archived at /app/operator for power users.  Same backend endpoints, same
// bearer token in localStorage — only the framing and language change.
// ---------------------------------------------------------------------------

type Severity = "info" | "warn" | "alert";

type Event = {
  id: number;
  ts: string;
  source: string;
  severity: Severity;
  kind: string;
  summary: string;
  details_json: string;
};

type ChainStatus = {
  ok: boolean;
  count: number;
  broken_at: number | null;
  head: string;
};

type ScanReport = {
  ok: boolean;
  elapsed_ms: number;
  new_alerts: number;
  new_warns: number;
  new_events_total: number;
  stages: {
    urlhaus: { hosts_loaded: number | null; status: string };
    fim: { baselined_paths: number; new_findings: number };
    canary: { planted: number; new_findings: number };
    defender: { new_events: number };
    firewall: { new_events: number };
  };
};

type PerfFinding = {
  id: string;
  category: string;
  severity: "ok" | "info" | "opportunity" | "warn" | "critical";
  title: string;
  current: string;
  recommended: string;
  fix_command: string | null;
  requires_admin: boolean;
};

type PerfReport = {
  elapsed_ms: number;
  host: {
    os_name: string;
    os_version: string;
    cpu_brand: string;
    mem_total_gb: number;
    mem_used_gb: number;
    uptime_hours: number;
  };
  findings: PerfFinding[];
};

type Risk = "ok" | "watch" | "concern" | "danger";

// Translate raw event into a layperson-readable headline + risk band.
function explain(ev: Event): { risk: Risk; title: string; detail: string } {
  let d: Record<string, unknown> = {};
  try { d = JSON.parse(ev.details_json) as Record<string, unknown>; } catch {}
  const exe = String(d.exe ?? "");
  const path = String(d.path ?? "");
  const host = String(d.host ?? d.domain ?? "");
  const k = `${ev.source}/${ev.kind}`;
  const exeName = exe.split(/[\\/]/).pop() || exe;

  if (k === "dns/urlhaus_hit") {
    return {
      risk: "danger",
      title: `A program tried to reach a known-malicious website`,
      detail: host ? `Blocked connection to ${host}. This domain is on the URLhaus malware list.` : `Connection blocked. The destination is on the URLhaus malware list.`,
    };
  }
  if (k === "canary/canary_tampered" || k === "canary/canary_modified" || k === "canary/canary_deleted") {
    return {
      risk: "danger",
      title: `A decoy file was touched — someone is snooping`,
      detail: `Bastion planted hidden bait files in your account. Something just modified one. Real software has no reason to touch these.`,
    };
  }
  if (k === "fim/file_modified" && path.toLowerCase().endsWith("hosts")) {
    return {
      risk: "danger",
      title: `Your Windows hosts file was modified`,
      detail: `Malware often edits this file to redirect your bank, email, or login pages to fake versions. Review the change immediately.`,
    };
  }
  if (k === "fim/file_added") {
    return { risk: "concern", title: `New file appeared in a watched system folder`, detail: path || "(no path)" };
  }
  if (k === "fim/file_modified") {
    return { risk: "concern", title: `A protected system file changed`, detail: path || "(no path)" };
  }
  if (k.startsWith("defender/") && ev.severity === "alert") {
    return { risk: "danger", title: `Windows Defender flagged malware`, detail: ev.summary };
  }
  if (k.startsWith("firewall/") && ev.severity === "alert") {
    return { risk: "concern", title: `Firewall configuration changed`, detail: ev.summary };
  }
  if (k === "proc_fp/proc_fp_novel") {
    const lower = path.toLowerCase();
    const inTemp = lower.includes("\\temp\\") || lower.includes("\\downloads\\") || lower.includes("\\appdata\\local\\temp\\");
    if (inTemp) {
      return {
        risk: "concern",
        title: `Unknown program launched from a temp folder`,
        detail: `${exeName} ran from ${path}. Programs run from temp folders are unusual — check that you started this yourself.`,
      };
    }
    return {
      risk: "watch",
      title: `New program seen for the first time`,
      detail: `${exeName} ran with a fingerprint Bastion hasn't seen before. Likely an update; review if you didn't install anything recently.`,
    };
  }
  if (ev.source === "response") {
    return { risk: "ok", title: `Bastion took action`, detail: ev.summary };
  }
  if (ev.severity === "alert") {
    return { risk: "danger", title: ev.summary || ev.kind, detail: "" };
  }
  if (ev.severity === "warn") {
    return { risk: "concern", title: ev.summary || ev.kind, detail: "" };
  }
  return { risk: "ok", title: ev.summary || ev.kind, detail: "" };
}

const RISK_STYLE: Record<Risk, { bg: string; ring: string; text: string; dot: string; label: string }> = {
  danger:  { bg: "bg-rose-500/10",  ring: "ring-rose-500/40",  text: "text-rose-300",  dot: "bg-rose-400",  label: "Action needed" },
  concern: { bg: "bg-amber-500/10", ring: "ring-amber-500/40", text: "text-amber-300", dot: "bg-amber-400", label: "Worth a look" },
  watch:   { bg: "bg-sky-500/10",   ring: "ring-sky-500/30",   text: "text-sky-300",   dot: "bg-sky-400",   label: "FYI" },
  ok:      { bg: "bg-emerald-500/10", ring: "ring-emerald-500/30", text: "text-emerald-300", dot: "bg-emerald-400", label: "All good" },
};

function relTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return iso;
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

// ---------------------------------------------------------------------------

export default function ConsoleHome() {
  const [hasLicense, setHasLicense] = useState(false);
  const [licenseInput, setLicenseInput] = useState("");
  const [licenseError, setLicenseError] = useState("");

  const [token, setToken] = useState<string>("");
  const [tokenInput, setTokenInput] = useState<string>("");

  const [events, setEvents] = useState<Event[]>([]);
  const [chain, setChain] = useState<ChainStatus | null>(null);
  const [ackedIds, setAckedIds] = useState<Set<number>>(new Set());
  const [linkError, setLinkError] = useState<string>("");

  const [scanning, setScanning] = useState(false);
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [perfRunning, setPerfRunning] = useState(false);
  const [perfReport, setPerfReport] = useState<PerfReport | null>(null);
  const [perfFixed, setPerfFixed] = useState<Set<string>>(new Set());
  const [showSetup, setShowSetup] = useState(false);

  // ---- license + token hydration -----------------------------------------

  useEffect(() => {
    try {
      if (localStorage.getItem("bastion_license")) setHasLicense(true);
      const t = localStorage.getItem("bastion_token");
      if (t) setToken(t);
    } catch {}
  }, []);

  function unlockWithKey() {
    const key = licenseInput.replace(/\s+/g, "");
    if (!key) { setLicenseError("paste your access key"); return; }
    setLicenseError("");
    fetch("/api/access/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key }),
    })
      .then(async (res) => {
        const data = await res.json().catch(() => ({ ok: false }));
        if (!res.ok || !data.ok) throw new Error(data?.message || "key validation failed");
        localStorage.setItem("bastion_license", key);
        setHasLicense(true);
      })
      .catch((err) => setLicenseError(String(err.message || err)));
  }

  // ---- triage hydration (server-backed) ----------------------------------

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("http://127.0.0.1:7878/api/triage", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data = (await res.json()) as { ids: number[] };
        if (!cancelled && Array.isArray(data.ids)) setAckedIds(new Set(data.ids));
      } catch {}
    })();
    return () => { cancelled = true; };
  }, [token]);

  // ---- live event + chain polling ----------------------------------------

  const pull = useCallback(async () => {
    if (!token) return;
    try {
      const [evRes, chRes] = await Promise.all([
        fetch("http://127.0.0.1:7878/api/events?limit=50", { headers: { Authorization: `Bearer ${token}` } }),
        fetch("http://127.0.0.1:7878/api/chain/verify", { headers: { Authorization: `Bearer ${token}` } }),
      ]);
      if (!evRes.ok) {
        setLinkError(evRes.status === 401 ? "token-rejected" : `agent returned HTTP ${evRes.status}`);
        return;
      }
      setLinkError("");
      const evJson = await evRes.json().catch(() => ({ events: [] }));
      setEvents(Array.isArray(evJson.events) ? evJson.events : []);
      if (chRes.ok) {
        const chJson = await chRes.json().catch(() => null);
        if (chJson) setChain(chJson);
      }
    } catch {
      setLinkError("agent-unreachable");
    }
  }, [token]);

  useEffect(() => {
    if (!token) return;
    pull();
    const id = setInterval(pull, 4000);
    return () => clearInterval(id);
  }, [token, pull]);

  // ---- derived ------------------------------------------------------------

  const visible = useMemo(() => events.filter((e) => !ackedIds.has(e.id)), [events, ackedIds]);

  const overallStatus = useMemo<{ risk: Risk; headline: string; sub: string; action?: { label: string; onClick: () => void } }>(() => {
    if (linkError === "token-rejected") return {
      risk: "concern",
      headline: "Reconnect needed",
      sub: "The agent is running but doesn't recognise this token. Paste the current one from your PC to resume monitoring.",
      action: { label: "Reconnect", onClick: resetToken },
    };
    if (linkError === "agent-unreachable") return {
      risk: "watch",
      headline: "Agent offline",
      sub: "Bastion isn't running on this machine. Launch it from your Start menu to resume monitoring.",
    };
    if (linkError) return { risk: "watch", headline: "Agent issue", sub: linkError };
    if (chain && !chain.ok) return { risk: "danger", headline: "Audit log was tampered with", sub: `Chain broke at event ${chain.broken_at}. Treat the machine as compromised.` };
    const danger  = visible.filter((e) => explain(e).risk === "danger").length;
    const concern = visible.filter((e) => explain(e).risk === "concern").length;
    if (danger  > 0) return { risk: "danger",  headline: `${danger} thing${danger === 1 ? "" : "s"} need${danger === 1 ? "s" : ""} your attention`, sub: "Review the items below and decide whether to resolve or investigate." };
    if (concern > 0) return { risk: "concern", headline: `${concern} item${concern === 1 ? "" : "s"} worth a look`, sub: "Probably nothing — but a human eye is recommended." };
    return { risk: "ok", headline: "You're protected", sub: events.length ? "Recent activity looks normal." : "Quiet so far — Bastion will tell you if anything changes." };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkError, chain, visible, events.length]);

  // ---- mutators -----------------------------------------------------------

  async function postTriage(path: "resolve" | "unresolve", ids: number[]) {
    if (!token || ids.length === 0) return false;
    try {
      const res = await fetch(`http://127.0.0.1:7878/api/triage/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ ids }),
      });
      return res.ok;
    } catch { return false; }
  }

  async function resolveEvent(id: number) {
    const prev = new Set(ackedIds);
    const next = new Set(ackedIds); next.add(id);
    setAckedIds(next);
    if (!(await postTriage("resolve", [id]))) {
      setAckedIds(prev);
      alert("Couldn't save — agent unreachable.");
    }
  }

  async function runScan() {
    if (scanning || !token) return;
    setScanning(true);
    try {
      const res = await fetch("http://127.0.0.1:7878/api/scan/run", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        alert(res.status === 401 ? "Bearer token rejected." : `Scan failed: HTTP ${res.status}`);
        return;
      }
      const text = await res.text();
      if (text) setScanReport(JSON.parse(text) as ScanReport);
    } catch (e) {
      alert(`Scan error: ${e}`);
    } finally {
      setScanning(false);
      pull();
    }
  }

  async function runPerf() {
    if (perfRunning || !token) return;
    setPerfRunning(true);
    try {
      const res = await fetch("http://127.0.0.1:7878/api/perf/audit", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        alert(res.status === 401 ? "Bearer token rejected." : `Audit failed: HTTP ${res.status}`);
        return;
      }
      const text = await res.text();
      if (text) setPerfReport(JSON.parse(text) as PerfReport);
      setPerfFixed(new Set());
    } catch (e) {
      alert(`Audit error: ${e}`);
    } finally {
      setPerfRunning(false);
    }
  }

  function saveTokenFromInput() {
    const t = tokenInput.replace(/\s+/g, "");
    if (!t) return;
    try { localStorage.setItem("bastion_token", t); } catch {}
    setToken(t);
    setTokenInput("");
    setShowSetup(false);
  }

  function resetToken() {
    try { localStorage.removeItem("bastion_token"); } catch {}
    setToken("");
    setEvents([]);
    setChain(null);
    setShowSetup(true);
  }

  // ---- render: license gate ----------------------------------------------

  if (!hasLicense) {
    return (
      <main className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center px-4">
        <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900/60 p-8 shadow-xl">
          <div className="text-xs uppercase tracking-widest text-emerald-400 mb-2">Bastion Console</div>
          <h1 className="text-2xl font-semibold mb-2">Unlock your console</h1>
          <p className="text-sm text-zinc-400 mb-6">
            Get a free access key at <Link href="/" className="text-emerald-400 underline">bastion.quest</Link> — enter your email, $0.00 works.
          </p>
          <label className="block text-xs uppercase tracking-wider text-zinc-500 mb-2">Access key</label>
          <textarea
            value={licenseInput}
            onChange={(e) => setLicenseInput(e.target.value)}
            placeholder="BSTN.eyJ…"
            rows={3}
            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm font-mono text-emerald-300 focus:border-emerald-500 focus:outline-none resize-none"
          />
          {licenseError && <p className="mt-2 text-sm text-rose-400">{licenseError}</p>}
          <button
            onClick={unlockWithKey}
            className="mt-4 w-full rounded-lg bg-emerald-500 px-4 py-3 text-sm font-medium text-zinc-950 hover:bg-emerald-400 transition"
          >
            Unlock
          </button>
        </div>
      </main>
    );
  }

  // ---- render: setup wizard (no token yet OR user opened it) -------------

  if (!token || showSetup) {
    return <SetupWizard
      tokenInput={tokenInput}
      setTokenInput={setTokenInput}
      onSave={saveTokenFromInput}
      onCancel={token ? () => setShowSetup(false) : undefined}
    />;
  }

  // ---- render: main console ----------------------------------------------

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-900 bg-zinc-950/80 backdrop-blur sticky top-0 z-10">
        <div className="mx-auto max-w-5xl px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className={`size-2.5 rounded-full ${linkError ? "bg-amber-400" : "bg-emerald-400 animate-pulse"}`} aria-hidden />
            <span className="font-semibold tracking-tight">Bastion</span>
            <span className="text-xs text-zinc-500">
              {linkError === "token-rejected" ? "token mismatch" :
               linkError === "agent-unreachable" ? "agent offline" :
               linkError ? "issue" : "connected · 127.0.0.1"}
            </span>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <button onClick={resetToken} className="text-zinc-400 hover:text-zinc-200 transition">
              Reconnect
            </button>
            <Link href="/app/operator" className="text-zinc-500 hover:text-zinc-300 transition text-xs">
              Advanced view →
            </Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-5xl px-4 py-8 space-y-6">
        {/* Status hero */}
        <section className={`rounded-2xl border ring-1 p-6 ${RISK_STYLE[overallStatus.risk].bg} ${RISK_STYLE[overallStatus.risk].ring} border-transparent`}>
          <div className="flex items-start gap-4">
            <StatusGlyph risk={overallStatus.risk} />
            <div className="flex-1 min-w-0">
              <h1 className={`text-2xl font-semibold ${RISK_STYLE[overallStatus.risk].text}`}>{overallStatus.headline}</h1>
              <p className="mt-1 text-zinc-400">{overallStatus.sub}</p>
              {overallStatus.action && (
                <button
                  onClick={overallStatus.action.onClick}
                  className="mt-4 rounded-lg bg-emerald-500 px-4 py-2 text-sm font-medium text-zinc-950 hover:bg-emerald-400 transition"
                >
                  {overallStatus.action.label}
                </button>
              )}
            </div>
          </div>
        </section>

        {/* Quick actions */}
        <section className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <ActionCard
            title="Run a full scan"
            sub="Checks files, network, and decoys. ~10–30s."
            busy={scanning}
            busyLabel="Scanning…"
            onClick={runScan}
            primary
          />
          <ActionCard
            title="Check performance"
            sub="What's slowing your PC down."
            busy={perfRunning}
            busyLabel="Auditing…"
            onClick={runPerf}
          />
          <ActionCard
            title="Reconnect agent"
            sub="Re-paste the token from your PC."
            onClick={resetToken}
          />
        </section>

        {/* Recent activity */}
        <section>
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-lg font-semibold">Recent activity</h2>
            <div className="text-xs text-zinc-500">
              {events.length} total · {visible.length} unresolved
            </div>
          </div>
          {events.length === 0 ? (
            <EmptyState linkError={linkError} />
          ) : (
            <ul className="space-y-2">
              {events.slice(0, 12).map((ev) => {
                const ex = explain(ev);
                const acked = ackedIds.has(ev.id);
                const style = RISK_STYLE[ex.risk];
                return (
                  <li key={ev.id} className={`rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 ${acked ? "opacity-50" : ""}`}>
                    <div className="flex items-start gap-3">
                      <div className={`mt-1 size-2 rounded-full ${style.dot}`} aria-hidden />
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-baseline gap-x-2">
                          <span className={`text-xs uppercase tracking-wider font-medium ${style.text}`}>{style.label}</span>
                          <span className="text-xs text-zinc-500">{relTime(ev.ts)}</span>
                        </div>
                        <p className="mt-1 text-sm text-zinc-100">{ex.title}</p>
                        {ex.detail && <p className="mt-1 text-xs text-zinc-500 break-words">{ex.detail}</p>}
                      </div>
                      {!acked && (
                        <button
                          onClick={() => resolveEvent(ev.id)}
                          className="text-xs text-zinc-500 hover:text-emerald-400 transition whitespace-nowrap"
                          title="Mark as reviewed. The original event stays in the audit log."
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        <footer className="pt-8 pb-4 text-center text-xs text-zinc-600">
          Bastion is a defensive sensor. It does not block nation-state malware. If you believe you are targeted, escalate to{" "}
            <a className="text-zinc-400 hover:text-zinc-200" href="https://citizenlab.ca">Citizen Lab</a>{" "}or{" "}
            <a className="text-zinc-400 hover:text-zinc-200" href="https://accessnow.org/help">Access Now</a>.
        </footer>
      </div>

      {/* Scan results modal */}
      {scanReport && (
        <Modal onClose={() => setScanReport(null)} title="Scan complete">
          <p className="text-sm text-zinc-400">
            Finished in {(scanReport.elapsed_ms / 1000).toFixed(1)}s.
          </p>
          <ul className="mt-4 space-y-2 text-sm">
            <ResultLine label="New things needing attention" value={scanReport.new_alerts} bad={scanReport.new_alerts > 0} />
            <ResultLine label="Worth a look" value={scanReport.new_warns} bad={scanReport.new_warns > 0} />
            <ResultLine label="Malware blocklist hosts loaded" value={scanReport.stages.urlhaus.hosts_loaded ?? "—"} />
            <ResultLine label="Files watched" value={scanReport.stages.fim.baselined_paths} />
            <ResultLine label="Decoys planted" value={scanReport.stages.canary.planted} />
          </ul>
          <button
            onClick={() => setScanReport(null)}
            className="mt-6 w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-emerald-400 transition"
          >
            OK
          </button>
        </Modal>
      )}

      {/* Perf results modal */}
      {perfReport && (
        <Modal onClose={() => setPerfReport(null)} title="Performance check">
          <p className="text-sm text-zinc-400">
            {perfReport.host.cpu_brand} · {perfReport.host.mem_used_gb.toFixed(1)} / {perfReport.host.mem_total_gb.toFixed(1)} GB RAM used · up {perfReport.host.uptime_hours.toFixed(1)}h
          </p>
          {perfReport.findings.length === 0 ? (
            <p className="mt-4 text-sm text-emerald-300">Nothing obvious to fix — your machine is in good shape.</p>
          ) : (
            <ul className="mt-4 space-y-2">
              {perfReport.findings.map((f) => (
                <PerfFindingRow
                  key={f.id}
                  finding={f}
                  token={token}
                  fixed={perfFixed.has(f.id)}
                  onFixed={() => setPerfFixed((prev) => new Set(prev).add(f.id))}
                />
              ))}
            </ul>
          )}
          <button
            onClick={() => setPerfReport(null)}
            className="mt-6 w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-medium text-zinc-950 hover:bg-emerald-400 transition"
          >
            Close
          </button>
        </Modal>
      )}
    </main>
  );
}

// ---------------------------------------------------------------------------

function StatusGlyph({ risk }: { risk: Risk }) {
  const cls = `size-12 rounded-xl flex items-center justify-center text-2xl ${
    risk === "danger" ? "bg-rose-500/20 text-rose-300" :
    risk === "concern" ? "bg-amber-500/20 text-amber-300" :
    risk === "watch" ? "bg-sky-500/20 text-sky-300" :
    "bg-emerald-500/20 text-emerald-300"
  }`;
  const ch = risk === "danger" ? "!" : risk === "concern" ? "?" : risk === "watch" ? "i" : "✓";
  return <div className={cls} aria-hidden>{ch}</div>;
}

function ActionCard({ title, sub, onClick, busy, busyLabel, primary }: {
  title: string; sub: string; onClick: () => void; busy?: boolean; busyLabel?: string; primary?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className={`text-left rounded-xl border p-4 transition disabled:opacity-60 ${
        primary
          ? "border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20"
          : "border-zinc-800 bg-zinc-900/40 hover:bg-zinc-900/80"
      }`}
    >
      <div className={`text-sm font-medium ${primary ? "text-emerald-200" : "text-zinc-100"}`}>
        {busy ? (busyLabel ?? "Working…") : title}
      </div>
      <div className="mt-1 text-xs text-zinc-500">{sub}</div>
    </button>
  );
}

function ResultLine({ label, value, bad }: { label: string; value: number | string; bad?: boolean }) {
  return (
    <li className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950/60 px-3 py-2">
      <span className="text-zinc-400">{label}</span>
      <span className={`font-mono ${bad ? "text-rose-300" : "text-zinc-200"}`}>{value}</span>
    </li>
  );
}

function EmptyState({ linkError }: { linkError: string }) {
  return (
    <div className="rounded-xl border border-dashed border-zinc-800 p-8 text-center">
      {linkError ? (
        <p className="text-xs text-zinc-500">Once the agent reconnects, recent activity will appear here.</p>
      ) : (
        <>
          <p className="text-zinc-300">Nothing here yet.</p>
          <p className="mt-2 text-xs text-zinc-500">Bastion is watching. Anything notable will appear here within seconds.</p>
        </>
      )}
    </div>
  );
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 bg-zinc-950/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[85vh] flex flex-col rounded-2xl border border-zinc-800 bg-zinc-900 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between p-6 pb-3 border-b border-zinc-800">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="text-zinc-500 hover:text-zinc-200">✕</button>
        </div>
        <div className="overflow-y-auto p-6 pt-4">
          {children}
        </div>
      </div>
    </div>
  );
}

function PerfFindingRow({ finding, token, fixed, onFixed }: {
  finding: PerfFinding;
  token: string;
  fixed: boolean;
  onFixed: () => void;
}) {
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string>("");
  const f = finding;
  const canFix = !!f.fix_command && !fixed;

  async function applyFix() {
    if (!f.fix_command || applying) return;
    setApplying(true); setError("");
    try {
      const res = await fetch("http://127.0.0.1:7878/api/perf/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ fix_command: f.fix_command }),
      });
      if (!res.ok) {
        setError(res.status === 403 ? "Agent rejected the fix." : `HTTP ${res.status}`);
        return;
      }
      onFixed();
    } catch (e) {
      setError(`Couldn't reach agent: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setApplying(false);
    }
  }

  const sevPill =
    f.severity === "critical" ? "text-rose-400" :
    f.severity === "warn" ? "text-amber-400" :
    f.severity === "opportunity" ? "text-sky-400" : "text-zinc-500";

  return (
    <li className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm text-zinc-100">{f.title}</p>
          <p className="mt-0.5 text-xs text-zinc-500">Now: {f.current} → Recommended: {f.recommended}</p>
          {f.fix_command && (
            <p className="mt-1 text-[10px] font-mono text-zinc-600 break-all">{f.fix_command}</p>
          )}
          {error && <p className="mt-1 text-xs text-rose-400">{error}</p>}
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          <span className={`text-[10px] uppercase tracking-wider whitespace-nowrap ${sevPill}`}>
            {fixed ? "fixed ✓" : f.severity}
          </span>
          {canFix && (
            <button
              onClick={applyFix}
              disabled={applying}
              className="rounded-md bg-emerald-500/90 px-2.5 py-1 text-xs font-medium text-zinc-950 hover:bg-emerald-400 disabled:opacity-60 transition whitespace-nowrap"
              title={f.requires_admin ? "Will prompt for admin (UAC)" : undefined}
            >
              {applying ? "Applying…" : f.requires_admin ? "Fix (admin)" : "Fix it"}
            </button>
          )}
        </div>
      </div>
    </li>
  );
}

function SetupWizard({ tokenInput, setTokenInput, onSave, onCancel }: {
  tokenInput: string;
  setTokenInput: (v: string) => void;
  onSave: () => void;
  onCancel?: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100 px-4 py-12">
      <div className="mx-auto max-w-2xl">
        <div className="text-xs uppercase tracking-widest text-emerald-400 mb-2">Set up Bastion</div>
        <h1 className="text-3xl font-semibold mb-2">Connect this console to your PC</h1>
        <p className="text-zinc-400 mb-8">
          The Bastion agent runs on your computer and reports here. Three steps, takes about a minute.
        </p>

        <div className="space-y-4">
          <Step n={1} title="Download the installer">
            <p className="text-sm text-zinc-400">Grab the latest Windows installer from GitHub.</p>
            <a
              href="https://github.com/1800bobrossdotcom-byte/bastion/releases/latest"
              className="mt-3 inline-flex items-center gap-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 px-4 py-2 text-sm transition"
              target="_blank" rel="noopener noreferrer"
            >
              Download BASTION_x64-setup.exe ↗
            </a>
          </Step>

          <Step n={2} title="Run it once">
            <p className="text-sm text-zinc-400">
              The installer registers Bastion to start with Windows. After install, the agent runs in the background and exposes a local-only API at <code className="text-zinc-300">127.0.0.1:7878</code>.
            </p>
            <p className="mt-2 text-xs text-zinc-500">Nothing is sent off your machine. The cloud console is read-only over a token you control.</p>
          </Step>

          <Step n={3} title="Paste your agent token">
            <p className="text-sm text-zinc-400">
              The agent printed a token on first run and saved it to a file on your PC. To find it:
            </p>
            <ol className="mt-3 space-y-2 text-sm text-zinc-400 list-decimal pl-5">
              <li>
                Press <kbd className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-300">Win</kbd> + <kbd className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-300">R</kbd> to open the Run box.
              </li>
              <li>
                <div className="flex flex-wrap items-center gap-2">
                  <span>Paste this path and press Enter:</span>
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText("%APPDATA%\\bastion\\bastion\\data");
                        setCopied(true);
                        setTimeout(() => setCopied(false), 1500);
                      } catch {}
                    }}
                    className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800 transition"
                  >
                    {copied ? "Copied ✓" : "Copy path"}
                  </button>
                </div>
                <code className="mt-2 block rounded bg-zinc-900 border border-zinc-800 px-3 py-2 text-xs text-zinc-300 break-all">
                  %APPDATA%\bastion\bastion\data
                </code>
              </li>
              <li>
                A folder opens. Double-click <code className="text-zinc-300">token.txt</code> (Notepad opens it).
              </li>
              <li>
                Select all (<kbd className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-300">Ctrl</kbd>+<kbd className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-300">A</kbd>), copy (<kbd className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-300">Ctrl</kbd>+<kbd className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-300">C</kbd>), then paste it below.
              </li>
            </ol>
            <textarea
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="paste the token here"
              rows={2}
              className="mt-3 w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm font-mono text-emerald-300 focus:border-emerald-500 focus:outline-none resize-none"
            />
            <div className="mt-3 flex gap-2">
              <button
                onClick={onSave}
                disabled={!tokenInput.trim()}
                className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-medium text-zinc-950 hover:bg-emerald-400 disabled:opacity-50 transition"
              >
                Connect
              </button>
              {onCancel && (
                <button onClick={onCancel} className="rounded-lg border border-zinc-800 px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-900 transition">
                  Cancel
                </button>
              )}
            </div>
          </Step>
        </div>

        <p className="mt-8 text-center text-xs text-zinc-600">
          Power user? The full operator view is at <Link href="/app/operator" className="text-zinc-400 hover:text-zinc-200">/app/operator</Link>.
        </p>
      </div>
    </main>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="flex items-center gap-3 mb-2">
        <div className="size-7 rounded-full bg-emerald-500/20 text-emerald-300 flex items-center justify-center text-sm font-medium">{n}</div>
        <h3 className="font-medium">{title}</h3>
      </div>
      <div className="ml-10">{children}</div>
    </div>
  );
}
