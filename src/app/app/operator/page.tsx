"use client";

import { useEffect, useRef, useState } from "react";

type Event = {
  id: number;
  ts: string;
  source: string;
  severity: "info" | "warn" | "alert";
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

type VaultEntry = {
  vault_id: string;
  original_path: string;
  sha256: string;
  size: number;
  mtime?: string;
  quarantined_at: string;
  reason: string;
  vault_bin_exists?: boolean;
};

type ScanReport = {
  ok: boolean;
  elapsed_ms: number;
  stages: {
    urlhaus: { hosts_loaded: number | null; status: string };
    fim: { baselined_paths: number; new_findings: number };
    canary: { planted: number; new_findings: number };
    defender: { new_events: number };
    firewall: { new_events: number };
  };
  new_alerts: number;
  new_warns: number;
  new_events_total: number;
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

type PerfApplyOutcome = {
  launched_elevated: boolean;
  ok: boolean;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  message: string;
};

type PerfReport = {
  elapsed_ms: number;
  host: {
    os_name: string;
    os_version: string;
    kernel: string;
    cpu_brand: string;
    cpu_cores_physical: number;
    cpu_cores_logical: number;
    mem_total_gb: number;
    mem_used_gb: number;
    mem_avail_gb: number;
    uptime_hours: number;
  };
  findings: PerfFinding[];
  gpu: {
    name: string;
    driver_version: string;
    vram_total_mb: number;
    vram_used_mb: number;
    vram_free_mb: number;
    utilization_pct: number;
    temperature_c: number;
  } | null;
  top_cpu: { pid: number; name: string; cpu_pct: number; mem_mb: number }[];
  top_mem: { pid: number; name: string; cpu_pct: number; mem_mb: number }[];
};

type ConnectorConfig = {
  kind: string;
  name: string;
  enabled: boolean;
  secret: string;
  config_json: string;
  updated_at: string;
};

type SentinelPullResult = {
  ok: boolean;
  pulled: number;
  ingested: number;
  mode: string;
  message?: string;
  items: { title: string; severity: string; status: string }[];
};

type Risk = "noise" | "info" | "review" | "suspicious" | "critical";

type WhyExplanation = {
  manager: string;
  mode: string;
  confidence: number;
  target: string;
  question: string;
  narrative: string;
  source_chain: string[];
  actions: string[];
  warnings: string[];
  evidence: unknown;
};

type WhyRowState = {
  open: boolean;
  loading?: boolean;
  data?: WhyExplanation;
  error?: string;
};

// Lightweight client-side classifier: looks at (source, kind, exe path, etc.)
// and returns a triage badge so the user can see at a glance whether a row
// is chrome-noise vs an actual hosts-file tamper. This is heuristic only —
// the merkle chain still records every raw event.
function assessRisk(ev: Event): { risk: Risk; why: string } {
  let d: Record<string, unknown> = {};
  try { d = JSON.parse(ev.details_json) as Record<string, unknown>; } catch {}
  const exe = String(d.exe ?? "").toLowerCase();
  const path = String(d.path ?? "").toLowerCase();
  const parent = String(d.parent ?? "").toLowerCase();
  const k = `${ev.source}/${ev.kind}`;

  // Hard-critical signals.
  if (k === "dns/urlhaus_hit") return { risk: "critical", why: "host on URLhaus malware list" };
  if (k === "canary/canary_tampered" || k === "canary/canary_modified" || k === "canary/canary_deleted")
    return { risk: "critical", why: "decoy file touched — something is enumerating you" };
  if (k === "fim/file_modified" && path.endsWith("hosts"))
    return { risk: "critical", why: "hosts file modified — likely DNS hijack" };
  if (k === "fim/file_added" || k === "fim/file_modified")
    return { risk: "suspicious", why: "watched system file changed" };

  // proc_fp triage — the main noise source.
  if (k === "proc_fp/proc_fp_novel") {
    const inProgFiles = path.includes("\\program files\\") || path.includes("\\program files (x86)\\");
    const inWindows = path.startsWith("c:\\windows\\");
    const inTemp = path.includes("\\temp\\") || path.includes("\\appdata\\local\\temp\\") || path.includes("\\downloads\\");
    const isBrowser = exe.endsWith("chrome.exe") || exe.endsWith("msedge.exe") || exe.endsWith("firefox.exe") || exe.endsWith("brave.exe");
    const isShell = exe.endsWith("conhost.exe") && (parent.endsWith("powershell.exe") || parent.endsWith("pwsh.exe") || parent.endsWith("cmd.exe"));
    if (inTemp) return { risk: "suspicious", why: "new fingerprint launched from temp/download dir" };
    if (isBrowser && inProgFiles) return { risk: "noise", why: "browser arg variation — expected" };
    if (isShell) return { risk: "noise", why: "interactive shell session" };
    if (inProgFiles || inWindows) return { risk: "review", why: "signed binary, novel arg pattern" };
    return { risk: "review", why: "novel process fingerprint" };
  }

  if (k.startsWith("defender/") && ev.severity === "alert") return { risk: "critical", why: "Defender flagged malware" };
  if (k.startsWith("firewall/") && ev.severity === "alert") return { risk: "critical", why: "firewall config changed" };
  if (ev.source === "response") return { risk: "info", why: "agent action" };
  if (ev.severity === "info") return { risk: "info", why: "" };
  return { risk: "review", why: "" };
}

const RISK_CLASS: Record<Risk, string> = {
  critical: "text-[color:var(--color-red)] border-[color:var(--color-red)]",
  suspicious: "text-[color:var(--color-amber)] border-[color:var(--color-amber)]",
  review: "text-[color:var(--color-phosphor)] border-[color:var(--color-phosphor-faint)]",
  noise: "text-[color:var(--color-phosphor-faint)] border-[color:var(--color-phosphor-faint)]",
  info: "text-[color:var(--color-phosphor-dim)] border-[color:var(--color-phosphor-faint)]",
};

const SEV_CHAR: Record<string, string> = { alert: "!!", warn: "**", info: ".." };
const SEV_CLASS: Record<string, string> = {
  alert: "text-[color:var(--color-red)]",
  warn: "text-[color:var(--color-amber)]",
  info: "text-[color:var(--color-phosphor-dim)]",
};

const BANNER = String.raw`
 ____    _    ____ _____ ___ ___  _   _
| __ )  / \  / ___|_   _|_ _/ _ \| \ | |
|  _ \ / _ \ \___ \ | |  | | | | |  \| |
| |_) / ___ \ ___) || |  | | |_| | |\  |
|____/_/   \_\____/ |_| |___\___/|_| \_|
`;

const BOOT_LINES = [
  "[ok] phosphor calibrated",
  "[ok] sensor link 127.0.0.1:7878",
  "[ok] merkle audit chain primed",
  "[ok] canary tokens planted",
  "[..] auth: awaiting bearer token",
];

export default function Home() {
  const [hasLicense, setHasLicense] = useState(false);
  const [licenseInput, setLicenseInput] = useState("");
  const [licenseError, setLicenseError] = useState("");
  const [token, setToken] = useState("");
  const [events, setEvents] = useState<Event[]>([]);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");
  const [lastTickAt, setLastTickAt] = useState<Date | null>(null);
  const [bootIdx, setBootIdx] = useState(0);
  const [chain, setChain] = useState<ChainStatus | null>(null);
  const [vault, setVault] = useState<VaultEntry[]>([]);
  const [showVault, setShowVault] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [perfReport, setPerfReport] = useState<PerfReport | null>(null);
  const [perfRunning, setPerfRunning] = useState(false);
  const [hideNoise, setHideNoise] = useState(true);
  const [sevFilter, setSevFilter] = useState<"all" | "alert" | "warn" | "info">("all");
  const [ackedIds, setAckedIds] = useState<Set<number>>(new Set());
  const [showResolved, setShowResolved] = useState(false);
  const [whyById, setWhyById] = useState<Record<number, WhyRowState>>({});
  const [connectors, setConnectors] = useState<ConnectorConfig[]>([]);
  const [sentinelDraft, setSentinelDraft] = useState({
    name: "Microsoft Sentinel",
    enabled: true,
    tenant_id: "",
    subscription_id: "",
    resource_group: "",
    workspace_name: "",
    notes: "",
  });
  const [sentinelPullResult, setSentinelPullResult] = useState<SentinelPullResult | null>(null);
  const [sentinelAuthStatus, setSentinelAuthStatus] = useState<{
    configured: boolean;
    az_available: boolean;
    workspace_reachable: boolean;
    user?: string;
    subscription?: string;
    message: string;
  } | null>(null);
  const tickerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("bastion_token") : null;
    if (stored) setToken(stored);

    const license = typeof window !== "undefined" ? localStorage.getItem("bastion_license") : null;
    if (license) setHasLicense(true);

    // Best-effort migration of any legacy localStorage triage state from the
    // previous client-side-only release.  Pulled into a one-shot push to the
    // agent below once we have a token.
  }, []);

  // Hydrate resolved triage from the agent whenever the token is set, and
  // migrate any legacy localStorage markers into the durable store.
  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    (async () => {
      // 1) one-shot migration of legacy markers (if any).
      const legacy =
        typeof window !== "undefined" ? localStorage.getItem("bastion_acked_ids") : null;
      if (legacy) {
        try {
          const arr = JSON.parse(legacy) as number[];
          if (Array.isArray(arr) && arr.length > 0) {
            await fetch("http://127.0.0.1:7878/api/triage/resolve", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify({ ids: arr, note: "migrated-from-localStorage" }),
            }).catch(() => {});
          }
          localStorage.removeItem("bastion_acked_ids");
        } catch {}
      }
      // 2) load the canonical resolved set from the agent.
      try {
        const res = await fetch("http://127.0.0.1:7878/api/triage", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data = (await res.json()) as { ids: number[] };
        if (!cancelled && Array.isArray(data.ids)) setAckedIds(new Set(data.ids));
      } catch {}
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  async function postTriage(path: "resolve" | "unresolve", ids: number[]) {
    if (!token || ids.length === 0) return false;
    try {
      const res = await fetch(`http://127.0.0.1:7878/api/triage/${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ ids }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async function resolveEvent(id: number) {
    const next = new Set(ackedIds);
    next.add(id);
    setAckedIds(next);
    const ok = await postTriage("resolve", [id]);
    if (!ok) {
      // roll back optimistic update on failure.
      const rollback = new Set(next);
      rollback.delete(id);
      setAckedIds(rollback);
      alert("triage save failed — agent unreachable. Resolve not persisted.");
    }
  }

  async function unresolveEvent(id: number) {
    const next = new Set(ackedIds);
    next.delete(id);
    setAckedIds(next);
    const ok = await postTriage("unresolve", [id]);
    if (!ok) {
      const rollback = new Set(next);
      rollback.add(id);
      setAckedIds(rollback);
      alert("triage save failed — agent unreachable. Reopen not persisted.");
    }
  }

  async function clearResolved() {
    if (ackedIds.size === 0) return;
    if (!confirm(`Forget ${ackedIds.size} resolved markers? Original events stay in the merkle chain.`)) return;
    const ids = Array.from(ackedIds);
    const prev = new Set(ackedIds);
    setAckedIds(new Set());
    const ok = await postTriage("unresolve", ids);
    if (!ok) {
      setAckedIds(prev);
      alert("triage clear failed — agent unreachable.");
    }
  }

  async function resolveAllVisible() {
    if (visible.length === 0) return;
    if (!confirm(`Mark all ${visible.length} visible events as resolved? Original events stay in the merkle chain.`)) return;
    const ids = visible.map((e) => e.id);
    const prev = new Set(ackedIds);
    const next = new Set(ackedIds);
    ids.forEach((id) => next.add(id));
    setAckedIds(next);
    const ok = await postTriage("resolve", ids);
    if (!ok) {
      setAckedIds(prev);
      alert("triage save failed — agent unreachable.");
    }
  }

  function unlockWithKey() {
    // Keys are base64url (case-sensitive) — only strip whitespace, do not change case.
    const key = licenseInput.replace(/\s+/g, "");
    if (!key) {
      setLicenseError("access key is required");
      return;
    }

    fetch("/api/access/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key }),
    })
      .then(async (res) => {
        const data = await res.json().catch(() => ({ ok: false }));
        if (!res.ok || !data.ok) {
          throw new Error(data?.message || "key validation failed");
        }
        localStorage.setItem("bastion_license", key);
        setHasLicense(true);
        setLicenseError("");
      })
      .catch((err) => {
        setLicenseError(String(err));
      });
  }

  useEffect(() => {
    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setBootIdx(i);
      if (i >= BOOT_LINES.length) clearInterval(id);
    }, 350);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const res = await fetch("http://127.0.0.1:7878/api/events?limit=500", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: Event[] = await res.json();
        if (!cancelled) {
          setEvents(data);
          setError("");
          setLastTickAt(new Date());
        }
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [token]);

  useEffect(() => {
    setWhyById({});
  }, [token]);

  async function refreshConnectors() {
    if (!token) return;
    try {
      const res = await fetch("http://127.0.0.1:7878/api/connectors", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return;
      const data: ConnectorConfig[] = await res.json();
      setConnectors(data);
      const sentinel = data.find((c) => c.kind === "sentinel");
      if (sentinel) {
        let parsed: Record<string, unknown> = {};
        try { parsed = JSON.parse(sentinel.config_json) as Record<string, unknown>; } catch {}
        setSentinelDraft({
          name: sentinel.name || "Microsoft Sentinel",
          enabled: sentinel.enabled,
          tenant_id: String(parsed.tenant_id ?? ""),
          subscription_id: String(parsed.subscription_id ?? ""),
          resource_group: String(parsed.resource_group ?? ""),
          workspace_name: String(parsed.workspace_name ?? ""),
          notes: String(parsed.notes ?? ""),
        });
      }
    } catch {
      /* connector panel is best-effort */
    }
  }

  useEffect(() => {
    if (!token) return;
    refreshConnectors();
    checkSentinelAuthStatus();
    const id = setInterval(() => {
      refreshConnectors();
      checkSentinelAuthStatus();
    }, 30000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const res = await fetch("http://127.0.0.1:7878/api/chain/verify", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data: ChainStatus = await res.json();
        if (!cancelled) setChain(data);
      } catch {
        /* main tick handles connectivity errors */
      }
    };
    tick();
    const id = setInterval(tick, 30000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [token]);

  const filteredBySource = filter === "all" ? events : events.filter((e) => e.source === filter);
  const filteredBySev = sevFilter === "all" ? filteredBySource : filteredBySource.filter((e) => e.severity === sevFilter);
  const filteredByNoise = hideNoise
    ? filteredBySev.filter((e) => assessRisk(e).risk !== "noise")
    : filteredBySev;
  const visible = showResolved ? filteredByNoise : filteredByNoise.filter((e) => !ackedIds.has(e.id));
  const noiseCount = filteredBySev.length - filteredByNoise.length;
  const resolvedHiddenCount = showResolved ? 0 : filteredByNoise.length - visible.length;
  // Counts are computed on unresolved events so the cards reflect what still needs attention.
  const liveEvents = events.filter((e) => !ackedIds.has(e.id));
  const counts = {
    alert: liveEvents.filter((e) => e.severity === "alert").length,
    warn: liveEvents.filter((e) => e.severity === "warn").length,
    info: liveEvents.filter((e) => e.severity === "info").length,
    removed: events.filter(
      (e) =>
        e.source === "response" &&
        (e.kind === "file_quarantined" || e.kind === "process_killed")
    ).length,
  };
  const sources = Array.from(new Set(events.map((e) => e.source))).sort();

  async function refreshVault(silent = true) {
    if (!token) return;
    try {
      const res = await fetch("http://127.0.0.1:7878/api/quarantine/list", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: VaultEntry[] = await res.json();
      setVault(data);
    } catch (e) {
      if (!silent) alert(`vault list error: ${e}`);
    }
  }

  useEffect(() => {
    if (!token) return;
    refreshVault(true);
    const id = setInterval(() => refreshVault(true), 15000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  async function runScan() {
    if (scanning) return;
    setScanning(true);
    try {
      const res = await fetch("http://127.0.0.1:7878/api/scan/run", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const hint = res.status === 401 ? " — bearer token rejected (click [reset token] above)" : "";
        alert(`scan failed: HTTP ${res.status}${hint}`);
        return;
      }
      const text = await res.text();
      if (!text) {
        alert("scan returned empty response");
        return;
      }
      setScanReport(JSON.parse(text) as ScanReport);
    } catch (e) {
      alert(`scan error: ${e}`);
    } finally {
      setScanning(false);
    }
  }

  async function runPerf() {
    if (perfRunning) return;
    setPerfRunning(true);
    try {
      const res = await fetch("http://127.0.0.1:7878/api/perf/audit", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const hint = res.status === 401 ? " — bearer token rejected (click [reset token] above)" : "";
        alert(`perf audit failed: HTTP ${res.status}${hint}`);
        return;
      }
      const text = await res.text();
      if (!text) {
        alert("perf audit returned empty response");
        return;
      }
      setPerfReport(JSON.parse(text) as PerfReport);
    } catch (e) {
      alert(`perf audit error: ${e}`);
    } finally {
      setPerfRunning(false);
    }
  }

  async function trustFp(fp: string, exe: string) {
    if (!confirm(`Trust this exact fingerprint?\n\n  exe: ${exe}\n  fp:  ${fp}\n\nFuture occurrences will be silently suppressed. Audit chain still records the trust action.`)) return;
    try {
      const res = await fetch("http://127.0.0.1:7878/api/trust/fp", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ fp, exe, reason: "trusted from dashboard" }),
      });
      if (res.ok) alert(`trusted fp ${fp.slice(0, 12)}…`);
      else alert(`trust failed: HTTP ${res.status}`);
    } catch (e) {
      alert(`trust error: ${e}`);
    }
  }

  async function trustExe(exe: string) {
    if (!confirm(`Bulk-trust ALL fingerprints for:\n\n  ${exe}\n\nThis silences every future proc_fp_novel from this exe. Useful for chrome.exe-style noise. The audit chain still records the trust decision and you can revoke it later.`)) return;
    try {
      const res = await fetch("http://127.0.0.1:7878/api/trust/exe", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ exe, reason: "bulk-trusted from dashboard" }),
      });
      if (res.ok) alert(`trusted exe ${exe}`);
      else alert(`trust failed: HTTP ${res.status}`);
    } catch (e) {
      alert(`trust error: ${e}`);
    }
  }

  async function killPid(pid: number, reason: string) {
    if (!confirm(`Force-kill PID ${pid}?\n\nReason: ${reason}\n\nThis cannot be undone.`)) return;
    try {
      const res = await fetch("http://127.0.0.1:7878/api/respond/kill-pid", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ pid, reason }),
      });
      const data = await res.json();
      alert(data.ok ? `killed pid ${pid}` : `kill failed: ${data.stderr || "unknown"}`);
    } catch (e) {
      alert(`kill error: ${e}`);
    }
  }

  async function quarantinePath(path: string, reason: string) {
    if (!confirm(`Quarantine\n\n${path}\n\nFile will be moved to vault (reversible). Continue?`)) return;
    try {
      const res = await fetch("http://127.0.0.1:7878/api/respond/quarantine", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ path, reason }),
      });
      if (res.ok) {
        const rec = await res.json();
        alert(
          rec.original_deleted
            ? `quarantined → vault/${rec.vault_id}.bin\noriginal removed`
            : `vault copy saved → ${rec.vault_id}\nWARNING: original NOT removed (locked or in use)`
        );
      } else {
        alert(`quarantine failed: HTTP ${res.status}`);
      }
    } catch (e) {
      alert(`quarantine error: ${e}`);
    }
  }

  async function saveSentinelConnector() {
    try {
      const res = await fetch("http://127.0.0.1:7878/api/connectors/sentinel", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(sentinelDraft),
      });
      if (!res.ok) {
        alert(`sentinel connector save failed: HTTP ${res.status}`);
        return;
      }
      await refreshConnectors();
      setSentinelPullResult(null);
      const data = await res.json();
      alert(`sentinel connector saved. secret: ${(data.secret as string).slice(0, 12)}…`);
    } catch (e) {
      alert(`sentinel connector error: ${e}`);
    }
  }

  async function checkSentinelAuthStatus() {
    if (!token) return;
    try {
      const res = await fetch("http://127.0.0.1:7878/api/connectors/sentinel/auth-status", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return;
      const data = await res.json();
      setSentinelAuthStatus(data);
    } catch {
      /* auth check is best-effort */
    }
  }

  async function pullSentinelIncidents() {
    try {
      const res = await fetch("http://127.0.0.1:7878/api/connectors/sentinel/pull", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ top: 20 }),
      });
      const data = (await res.json()) as SentinelPullResult;
      if (!res.ok || !data.ok) {
        setSentinelPullResult({
          ok: false,
          pulled: data.pulled ?? 0,
          ingested: data.ingested ?? 0,
          mode: data.mode ?? "azure_cli",
          message: data.message || `HTTP ${res.status}`,
          items: [],
        });
        return;
      }
      setSentinelPullResult(data);
    } catch (e) {
      setSentinelPullResult({ ok: false, pulled: 0, ingested: 0, mode: "azure_cli", message: String(e), items: [] });
    }
  }

  async function explainEvent(id: number) {
    const current = whyById[id];
    if (current?.open) {
      setWhyById((prev) => ({
        ...prev,
        [id]: { ...prev[id], open: false },
      }));
      return;
    }

    if (current?.data) {
      setWhyById((prev) => ({
        ...prev,
        [id]: { ...prev[id], open: true, error: undefined },
      }));
      return;
    }

    setWhyById((prev) => ({
      ...prev,
      [id]: { open: true, loading: true },
    }));

    try {
      const res = await fetch(`http://127.0.0.1:7878/api/why/event/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as WhyExplanation;
      setWhyById((prev) => ({
        ...prev,
        [id]: { open: true, loading: false, data },
      }));
    } catch (e) {
      setWhyById((prev) => ({
        ...prev,
        [id]: { open: true, loading: false, error: String(e) },
      }));
    }
  }

  if (!hasLicense) {
    return (
      <main className="min-h-dvh px-4 py-8 max-w-4xl mx-auto text-sm leading-relaxed">
        <section className="panel p-6 sm:p-8">
          <div className="text-[11px] tracking-[0.2em] uppercase text-[color:var(--color-ice)] mb-3">
            Bastion Console
          </div>
          <h1 className="text-3xl sm:text-4xl text-[color:var(--color-phosphor)] mb-3">
            Console access requires a license key.
          </h1>
          <p className="text-[color:var(--color-ice-dim)] mb-6 max-w-2xl">
            Get a free key at{" "}
            <a href="/" className="text-[color:var(--color-phosphor)] underline-offset-2 underline">bastion.quest</a>
            {" "}— enter your email and $0.00 for free. Your key arrives by email in seconds.
          </p>

          <div className="panel-subtle p-4 max-w-md">
            <label className="text-xs text-[color:var(--color-ice)] uppercase tracking-[0.12em]">
              Paste License Key
            </label>
            <div className="flex gap-2 mt-2 flex-wrap">
              <input
                value={licenseInput}
                onChange={(e) => setLicenseInput(e.target.value)}
                className="flex-1 min-w-[240px] bg-black/40 border border-[color:var(--color-line-soft)] px-2 py-2 outline-none text-[color:var(--color-phosphor)]"
                placeholder="BSTN.xxxxx.yyyyy"
              />
              <button onClick={unlockWithKey} className="btn-primary">Unlock</button>
            </div>
            {licenseError && <div className="text-[color:var(--color-amber)] text-xs mt-2">{licenseError}</div>}
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-dvh px-4 py-4 max-w-[1100px] mx-auto text-sm leading-snug">
      <pre className="text-[10px] sm:text-xs whitespace-pre overflow-x-auto">{BANNER}</pre>

      <div className="flex flex-wrap items-baseline justify-between gap-2 mt-1 mb-3 text-xs">
        <span className="text-[color:var(--color-phosphor-dim)]">
          v0.2 // local defensive sensor
        </span>
        <span className="text-[color:var(--color-phosphor-dim)]">
          link: 127.0.0.1:7878 {lastTickAt ? `· last ${lastTickAt.toLocaleTimeString()}` : ""}
        </span>
      </div>

      <div className="panel-subtle px-3 py-2 mb-3 text-xs text-[color:var(--color-ice-dim)]">
        Bastion is donation-supported — if you find it useful, BTC/ETH donations are welcome at bastion.quest.
      </div>

      <div className="box px-3 py-2 mb-3">
        {BOOT_LINES.slice(0, bootIdx).map((l, i) => (
          <div key={i} className="text-[color:var(--color-phosphor-dim)]">
            {l}
          </div>
        ))}
        {bootIdx >= BOOT_LINES.length && (
          <div className="text-[color:var(--color-phosphor)] cursor-blink">ready</div>
        )}
      </div>

      {!token && (
        <div className="box px-3 py-3 mb-3 max-w-2xl">
          <div className="text-[color:var(--color-amber)] mb-2">
            [auth] paste agent bearer token
          </div>
          <div className="text-[color:var(--color-phosphor-dim)] text-xs mb-2">
            agent stdout, also: %APPDATA%\bastion\bastion\data\token.txt
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[color:var(--color-phosphor-dim)]">{">"}</span>
            <input
              type="password"
              autoFocus
              className="flex-1 bg-transparent border-none outline-none text-[color:var(--color-phosphor)] placeholder:text-[color:var(--color-phosphor-faint)]"
              placeholder="0123abcd..."
              onChange={(e) => {
                const v = e.target.value.trim();
                setToken(v);
                if (v) localStorage.setItem("bastion_token", v);
              }}
            />
          </div>
        </div>
      )}

      {error && (
        <div className="box box-alert px-3 py-2 mb-3 flex items-center justify-between gap-3">
          <span>[link-down] {error}</span>
          <button
            type="button"
            className="btn-ghost text-xs whitespace-nowrap"
            title="Clear the saved bearer token and prompt for a new one. Use this if the agent rotated its token or you pasted the wrong value."
            onClick={() => {
              try { localStorage.removeItem("bastion_token"); } catch {}
              setToken("");
            }}
          >
            [reset token]
          </button>
        </div>
      )}

      {chain && !chain.ok && (
        <div className="box box-alert px-3 py-2 mb-3 animate-pulse">
          [tamper] event-log merkle chain BROKEN at id {chain.broken_at}. rows verified:{" "}
          {chain.count}. someone (or something) edited the audit log.
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
        <button
          onClick={() => setSevFilter((v) => (v === "alert" ? "all" : "alert"))}
          className={`box box-alert px-3 py-2 text-left hover:bg-[rgba(255,80,80,0.08)] cursor-pointer ${sevFilter === "alert" ? "ring-2 ring-[color:var(--color-red)]" : ""}`}
          title="Click to filter the stream to ALERT events only. Click again to clear."
        >
          <div className="text-[10px] opacity-70">ALERT {sevFilter === "alert" ? "·active" : ""}</div>
          <div className="text-2xl">{String(counts.alert).padStart(3, "0")}</div>
        </button>
        <button
          onClick={() => setSevFilter((v) => (v === "warn" ? "all" : "warn"))}
          className={`box box-warn px-3 py-2 text-left hover:bg-[rgba(255,200,80,0.08)] cursor-pointer ${sevFilter === "warn" ? "ring-2 ring-[color:var(--color-amber)]" : ""}`}
          title="Click to filter the stream to WARN events only. Click again to clear."
        >
          <div className="text-[10px] opacity-70">WARN {sevFilter === "warn" ? "·active" : ""}</div>
          <div className="text-2xl">{String(counts.warn).padStart(3, "0")}</div>
        </button>
        <button
          onClick={() => setSevFilter((v) => (v === "info" ? "all" : "info"))}
          className={`box box-info px-3 py-2 text-left hover:bg-[rgba(0,255,102,0.06)] cursor-pointer ${sevFilter === "info" ? "ring-2 ring-[color:var(--color-phosphor)]" : ""}`}
          title="Click to filter the stream to INFO events only. Click again to clear."
        >
          <div className="text-[10px] opacity-70">INFO {sevFilter === "info" ? "·active" : ""}</div>
          <div className="text-2xl">{String(counts.info).padStart(3, "0")}</div>
        </button>
        <button
          onClick={() => setShowVault((v) => !v)}
          className="box px-3 py-2 text-left hover:bg-[rgba(0,255,102,0.06)] cursor-pointer"
          title="Click to toggle the removed-items vault panel"
        >
          <div className="text-[10px] opacity-70 text-[color:var(--color-phosphor)]">REMOVED</div>
          <div className="text-2xl text-[color:var(--color-phosphor)]">
            {String(counts.removed).padStart(3, "0")}
          </div>
        </button>
      </div>

      <div className="box mb-3 p-3">
        <div className="flex items-center justify-between gap-3 flex-wrap mb-2">
          <div>
            <div className="text-[color:var(--color-phosphor)]">// plugin connector: microsoft sentinel</div>
            <div className="text-[10px] text-[color:var(--color-phosphor-dim)]">
              Optional ingest bridge. Sentinel incidents can be pushed here from a Logic App / playbook.
            </div>
          </div>
          <button
            onClick={saveSentinelConnector}
            className="px-3 py-1 border border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)] hover:bg-[rgba(0,255,102,0.12)] text-xs"
          >
            [save connector]
          </button>
          <button
            onClick={pullSentinelIncidents}
            className="px-3 py-1 border border-[color:var(--color-amber)] text-[color:var(--color-amber)] hover:bg-[rgba(255,176,0,0.12)] text-xs"
          >
            [pull incidents]
          </button>
        </div>

        <details className="mb-3 border border-[color:var(--color-phosphor-faint)] p-2">
          <summary className="cursor-pointer text-[10px] text-[color:var(--color-phosphor-dim)]">
            honesty scope
          </summary>
          <div className="mt-2 text-[10px] text-[color:var(--color-phosphor-dim)] leading-relaxed">
            This plugin ingests Sentinel incidents into bastion&apos;s local event stream. It does not replace Sentinel,
            does not query Azure on its own, and does not ship secrets to any cloud service. If you want cloud
            Sentinel to reach this desktop, place a tunnel or reverse proxy in front of the ingest URL.
          </div>
        </details>

        {sentinelAuthStatus && (
          <div className={`mb-3 border p-2 text-xs ${
            sentinelAuthStatus.workspace_reachable
              ? "border-[color:var(--color-phosphor)] bg-[rgba(0,255,102,0.04)]"
              : "border-[color:var(--color-phosphor-faint)]"
          }`}>
            <div className="flex items-center gap-2 mb-1">
              <span className={sentinelAuthStatus.workspace_reachable ? "text-[color:var(--color-phosphor)]" : "text-[color:var(--color-phosphor-dim)]"}>
                {sentinelAuthStatus.workspace_reachable ? "✓ Azure auth ready" : "○ Auth not ready"}
              </span>
              <button
                onClick={checkSentinelAuthStatus}
                className="text-[10px] px-1 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:text-[color:var(--color-phosphor)]"
              >
                test
              </button>
            </div>
            {sentinelAuthStatus.user && (
              <div className="text-[color:var(--color-phosphor-dim)]">user: {sentinelAuthStatus.user}</div>
            )}
            {sentinelAuthStatus.subscription && (
              <div className="text-[color:var(--color-phosphor-dim)]">subscription: {sentinelAuthStatus.subscription}</div>
            )}
            <div className="text-[10px] text-[color:var(--color-phosphor-faint)] mt-1">{sentinelAuthStatus.message}</div>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          <label className="flex flex-col gap-1">
            <span className="text-[color:var(--color-phosphor-dim)]">display name</span>
            <input
              className="bg-transparent border border-[color:var(--color-phosphor-faint)] px-2 py-1 outline-none text-[color:var(--color-phosphor)]"
              value={sentinelDraft.name}
              onChange={(e) => setSentinelDraft((v) => ({ ...v, name: e.target.value }))}
            />
          </label>
          <label className="flex items-center gap-2 mt-5 sm:mt-0">
            <input
              type="checkbox"
              checked={sentinelDraft.enabled}
              onChange={(e) => setSentinelDraft((v) => ({ ...v, enabled: e.target.checked }))}
            />
            <span className="text-[color:var(--color-phosphor-dim)]">enabled</span>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[color:var(--color-phosphor-dim)]">tenant id</span>
            <input
              className="bg-transparent border border-[color:var(--color-phosphor-faint)] px-2 py-1 outline-none text-[color:var(--color-phosphor)]"
              value={sentinelDraft.tenant_id}
              onChange={(e) => setSentinelDraft((v) => ({ ...v, tenant_id: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[color:var(--color-phosphor-dim)]">subscription id</span>
            <input
              className="bg-transparent border border-[color:var(--color-phosphor-faint)] px-2 py-1 outline-none text-[color:var(--color-phosphor)]"
              value={sentinelDraft.subscription_id}
              onChange={(e) => setSentinelDraft((v) => ({ ...v, subscription_id: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[color:var(--color-phosphor-dim)]">resource group</span>
            <input
              className="bg-transparent border border-[color:var(--color-phosphor-faint)] px-2 py-1 outline-none text-[color:var(--color-phosphor)]"
              value={sentinelDraft.resource_group}
              onChange={(e) => setSentinelDraft((v) => ({ ...v, resource_group: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[color:var(--color-phosphor-dim)]">workspace name</span>
            <input
              className="bg-transparent border border-[color:var(--color-phosphor-faint)] px-2 py-1 outline-none text-[color:var(--color-phosphor)]"
              value={sentinelDraft.workspace_name}
              onChange={(e) => setSentinelDraft((v) => ({ ...v, workspace_name: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1 sm:col-span-2">
            <span className="text-[color:var(--color-phosphor-dim)]">notes</span>
            <input
              className="bg-transparent border border-[color:var(--color-phosphor-faint)] px-2 py-1 outline-none text-[color:var(--color-phosphor)]"
              value={sentinelDraft.notes}
              onChange={(e) => setSentinelDraft((v) => ({ ...v, notes: e.target.value }))}
              placeholder="logic app, webhook, or tunnel notes"
            />
          </label>
        </div>

        {(() => {
          const sentinel = connectors.find((c) => c.kind === "sentinel");
          if (!sentinel) return null;
          return (
            <div className="mt-3 text-[10px] text-[color:var(--color-phosphor-dim)] space-y-1">
              <div>status: <span className="text-[color:var(--color-phosphor)]">{sentinel.enabled ? "enabled" : "disabled"}</span></div>
              <div>ingest url: <span className="break-all text-[color:var(--color-phosphor)]">http://127.0.0.1:7878/api/connectors/sentinel/ingest</span></div>
              <div>secret: <span className="break-all text-[color:var(--color-phosphor)]">{sentinel.secret}</span></div>
            </div>
          );
        })()}

        {sentinelPullResult && (
          <div className="mt-3 border border-[color:var(--color-phosphor-faint)] p-2 text-[10px] space-y-1">
            <div className={sentinelPullResult.ok ? "text-[color:var(--color-phosphor)]" : "text-[color:var(--color-amber)]"}>
              {sentinelPullResult.ok ? "[ok]" : "[warn]"} pulled {sentinelPullResult.pulled} incidents · ingested {sentinelPullResult.ingested} · auth {sentinelPullResult.mode}
            </div>
            {sentinelPullResult.message && (
              <div className="text-[color:var(--color-amber)]">{sentinelPullResult.message}</div>
            )}
            {sentinelPullResult.items.length > 0 && (
              <div className="space-y-1 text-[color:var(--color-phosphor-dim)]">
                {sentinelPullResult.items.slice(0, 5).map((item, idx) => (
                  <div key={idx}>
                    {item.severity} / {item.status} / {item.title}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex gap-1 flex-wrap mb-3 text-xs items-center">
        {["all", ...sources].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-2 py-1 border ${
              filter === s
                ? "border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)] bg-[rgba(0,255,102,0.08)]"
                : "border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)]"
            }`}
          >
            [{s}]
          </button>
        ))}
        <span className="flex-1" />
        <button
          onClick={() => setHideNoise((v) => !v)}
          className={`px-2 py-1 border text-xs ${
            hideNoise
              ? "border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)] bg-[rgba(0,255,102,0.08)]"
              : "border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)]"
          }`}
          title="When on, browser/shell noise (proc_fp_novel from signed binaries in Program Files) is hidden. Risk chips still mark every visible row."
        >
          [hide noise{noiseCount > 0 ? `: ${noiseCount}` : ""}]
        </button>
        <button
          onClick={() => setShowResolved((v) => !v)}
          className={`px-2 py-1 border text-xs ${
            showResolved
              ? "border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)] bg-[rgba(0,255,102,0.08)]"
              : "border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)]"
          }`}
          title="Toggle visibility of events you have already marked resolved. Resolved markers are stored locally; the audit chain is never modified."
        >
          [{showResolved ? "hiding none" : `show resolved${resolvedHiddenCount > 0 ? `: ${resolvedHiddenCount}` : ""}`}]
        </button>
        {token && visible.length > 0 && (
          <button
            onClick={resolveAllVisible}
            className="px-2 py-1 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:text-[color:var(--color-phosphor)] text-xs"
            title="Mark every currently visible row as resolved. Does not delete anything from the merkle chain."
          >
            [resolve {visible.length}]
          </button>
        )}
        {ackedIds.size > 0 && (
          <button
            onClick={clearResolved}
            className="px-2 py-1 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:text-[color:var(--color-phosphor)] text-xs"
            title="Forget local resolved markers. Events themselves are unaffected."
          >
            [reset triage: {ackedIds.size}]
          </button>
        )}
        {token && (
          <button
            onClick={runScan}
            disabled={scanning}
            className={`px-3 py-1 border border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)] hover:bg-[rgba(0,255,102,0.12)] ${
              scanning ? "opacity-50 cursor-wait" : ""
            }`}
            title="Force a full sweep: URLhaus refresh + FIM + canary + Defender/Firewall log poll"
          >
            {scanning ? "[scanning…]" : "[run full scan]"}
          </button>
        )}
        {token && (
          <button
            onClick={runPerf}
            disabled={perfRunning}
            className={`px-3 py-1 border border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)] hover:bg-[rgba(0,255,102,0.12)] ${
              perfRunning ? "opacity-50 cursor-wait" : ""
            }`}
            title="AI/dev workload performance audit: power plan, GPU/VRAM, RAM headroom, disk free, Defender exclusions, WSL memory cap, top CPU/RAM consumers"
          >
            {perfRunning ? "[auditing…]" : "[perf audit]"}
          </button>
        )}
      </div>

      {showVault && token && (
        <div className="box mb-3">
          <div className="px-3 py-1 border-b border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] text-xs flex justify-between">
            <span>// removed items vault ({vault.length})</span>
            <button
              onClick={() => refreshVault(false)}
              className="text-[color:var(--color-phosphor-dim)] hover:text-[color:var(--color-phosphor)]"
            >
              [refresh]
            </button>
          </div>
          <div className="divide-y divide-[color:var(--color-phosphor-faint)]">
            {vault.length === 0 && (
              <div className="px-3 py-3 text-[color:var(--color-phosphor-dim)] text-xs">
                no items quarantined yet
              </div>
            )}
            {vault.map((v) => (
              <div key={v.vault_id} className="px-3 py-1.5 text-xs">
                <div className="flex gap-3 items-baseline flex-wrap">
                  <span className="text-[color:var(--color-phosphor-faint)] text-[10px] tabular-nums">
                    {v.quarantined_at?.slice(0, 19).replace("T", " ")}
                  </span>
                  <span className="text-[color:var(--color-phosphor)] break-all">
                    {v.original_path}
                  </span>
                  <span className="text-[color:var(--color-phosphor-dim)] text-[10px]">
                    {v.size}b
                  </span>
                  {v.vault_bin_exists === false && (
                    <span className="text-[color:var(--color-amber)] text-[10px]">
                      [vault bin missing]
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-[color:var(--color-phosphor-faint)] ml-0 mt-0.5 break-all">
                  id={v.vault_id} sha={v.sha256.slice(0, 16)}… reason={v.reason}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div ref={tickerRef} className="box">
        <div className="px-3 py-1 border-b border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] text-xs flex justify-between flex-wrap gap-2">
          <span>// event stream</span>
          <span>
            {chain?.ok && (
              <span className="text-[color:var(--color-phosphor)] mr-3">
                chain ok · {chain.count} rows · head {chain.head.slice(0, 12)}
              </span>
            )}
            {visible.length} rows
          </span>
        </div>
        <div className="divide-y divide-[color:var(--color-phosphor-faint)]">
          {visible.map((e) => {
            let details: unknown = null;
            try {
              details = JSON.parse(e.details_json);
            } catch {}
            const sevCls = SEV_CLASS[e.severity] ?? "";
            const d = details as Record<string, unknown> | null;
            const pid = d && typeof d.pid === "number" ? (d.pid as number) : null;
            const path = d && typeof d.path === "string" ? (d.path as string) : null;
            const fp = d && typeof d.fp === "string" ? (d.fp as string) : null;
            const exe = d && typeof d.exe === "string" ? (d.exe as string) : null;
            const exeBase = exe ? exe.split(/[\\/]/).pop() ?? exe : null;
            const showRespond = e.severity !== "info" && e.source !== "response" && (pid !== null || path !== null);
            const isProcFpNovel = e.source === "proc_fp" && e.kind === "proc_fp_novel" && fp && exeBase;
            const { risk, why } = assessRisk(e);
            const whyState = whyById[e.id];
            return (
              <div key={e.id} className="px-3 py-1.5 hover:bg-[rgba(0,255,102,0.04)]">
                <div className="flex gap-3 items-baseline flex-wrap">
                  <span className="text-[color:var(--color-phosphor-faint)] text-[10px] tabular-nums">
                    {new Date(e.ts).toISOString().slice(11, 19)}
                  </span>
                  <span className={`${sevCls} text-[10px]`}>{SEV_CHAR[e.severity] ?? "  "}</span>
                  <span className="text-[color:var(--color-phosphor-dim)] text-[10px] uppercase w-[88px] shrink-0">
                    {e.source}
                  </span>
                  <span
                    className={`text-[10px] px-1 border ${RISK_CLASS[risk]}`}
                    title={why}
                  >
                    {risk}
                  </span>
                  <span className="text-[color:var(--color-phosphor)]">{e.summary}</span>
                </div>
                {details ? (
                  <pre className="text-[10px] text-[color:var(--color-phosphor-faint)] mt-0.5 ml-[124px] overflow-x-auto whitespace-pre-wrap break-all">
                    {JSON.stringify(details)}
                  </pre>
                ) : null}
                {showRespond && (
                  <div className="ml-[124px] mt-1 flex gap-2 text-[10px] flex-wrap">
                    <span className="text-[color:var(--color-phosphor-faint)]">{">"} respond:</span>
                    {pid !== null && (
                      <button
                        onClick={() => killPid(pid, `${e.source}/${e.kind}: ${e.summary}`)}
                        className="px-2 border border-[color:var(--color-red)] text-[color:var(--color-red)] hover:bg-[rgba(255,80,80,0.1)]"
                      >
                        [kill pid {pid}]
                      </button>
                    )}
                    {path !== null && (
                      <button
                        onClick={() => quarantinePath(path, `${e.source}/${e.kind}: ${e.summary}`)}
                        className="px-2 border border-[color:var(--color-amber)] text-[color:var(--color-amber)] hover:bg-[rgba(255,200,80,0.1)]"
                      >
                        [quarantine]
                      </button>
                    )}
                    {isProcFpNovel && fp && exeBase && (
                      <>
                        <button
                          onClick={() => trustFp(fp, exeBase)}
                          className="px-2 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:bg-[rgba(0,255,102,0.06)]"
                          title="Suppress this exact fingerprint forever"
                        >
                          [trust fp]
                        </button>
                        <button
                          onClick={() => trustExe(exeBase)}
                          className="px-2 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:bg-[rgba(0,255,102,0.06)]"
                          title={`Suppress ALL future proc_fp_novel events for ${exeBase}`}
                        >
                          [trust {exeBase}]
                        </button>
                      </>
                    )}
                  </div>
                )}
                <div className="ml-[124px] mt-1 flex gap-2 text-[10px] flex-wrap">
                  <span className="text-[color:var(--color-phosphor-faint)]">{">"} explain:</span>
                  <button
                    onClick={() => explainEvent(e.id)}
                    className="px-2 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:bg-[rgba(0,255,102,0.06)]"
                    title="Generate a causal explanation for this row (WiTR-style why chain + AI manager synthesis)"
                  >
                    {whyState?.loading ? "[why…]" : whyState?.open ? "[hide why]" : "[why]"}
                  </button>
                  {ackedIds.has(e.id) ? (
                    <button
                      onClick={() => unresolveEvent(e.id)}
                      className="px-2 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:text-[color:var(--color-phosphor)]"
                      title="Re-open this event. Removes the local resolved marker; the audit chain entry is unchanged."
                    >
                      [reopen]
                    </button>
                  ) : (
                    <button
                      onClick={() => resolveEvent(e.id)}
                      className="px-2 border border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)] hover:bg-[rgba(0,255,102,0.1)]"
                      title="Mark this event as resolved. Hides it from the stream and decrements the ALERT/WARN/INFO counters. Stored in localStorage; the merkle chain row is untouched."
                    >
                      [resolve]
                    </button>
                  )}
                </div>
                {whyState?.open && (
                  <div className="ml-[124px] mt-1 border border-[color:var(--color-phosphor-faint)] p-2 text-[10px]">
                    {whyState.loading && (
                      <div className="text-[color:var(--color-phosphor-dim)]">building explanation…</div>
                    )}
                    {whyState.error && (
                      <div className="text-[color:var(--color-amber)]">[why-error] {whyState.error}</div>
                    )}
                    {whyState.data && (
                      <div className="space-y-1">
                        <div className="text-[color:var(--color-phosphor-dim)]">
                          manager={whyState.data.manager} mode={whyState.data.mode} confidence={whyState.data.confidence.toFixed(2)}
                        </div>
                        <div className="text-[color:var(--color-phosphor)]">{whyState.data.narrative}</div>
                        {whyState.data.source_chain.length > 0 && (
                          <div className="text-[color:var(--color-phosphor-faint)]">
                            chain: {whyState.data.source_chain.join(" -> ")}
                          </div>
                        )}
                        {whyState.data.actions.length > 0 && (
                          <div className="text-[color:var(--color-phosphor-dim)]">
                            next: {whyState.data.actions.join(" | ")}
                          </div>
                        )}
                        {whyState.data.warnings.length > 0 && (
                          <div className="text-[color:var(--color-amber)]">
                            caveats: {whyState.data.warnings.join(" | ")}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
          {visible.length === 0 && token && !error && (
            <div className="px-3 py-3 text-[color:var(--color-phosphor-dim)] cursor-blink">
              waiting for events
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 text-[10px] text-[color:var(--color-phosphor-faint)] text-center">
        bastion is a defensive sensor. it does not block nation-state malware. escalate suspected
        targeting to citizenlab.ca / accessnow.org/help.
      </div>

      {scanReport && (
        <div
          className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4"
          onClick={() => setScanReport(null)}
        >
          <div
            className="box max-w-xl w-full p-4 bg-black"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-baseline mb-3">
              <span className="text-[color:var(--color-phosphor)]">// scan report</span>
              <button
                onClick={() => setScanReport(null)}
                className="text-[color:var(--color-phosphor-dim)] hover:text-[color:var(--color-phosphor)] text-xs"
              >
                [close]
              </button>
            </div>
            <div className="text-xs space-y-1 font-mono">
              <div className="text-[color:var(--color-phosphor-dim)]">
                elapsed: <span className="text-[color:var(--color-phosphor)]">{scanReport.elapsed_ms}ms</span>
              </div>
              <div className="border-t border-[color:var(--color-phosphor-faint)] my-2" />
              <ScanRow
                label="urlhaus blocklist"
                detail={
                  scanReport.stages.urlhaus.hosts_loaded != null
                    ? `${scanReport.stages.urlhaus.hosts_loaded} malicious hosts loaded`
                    : "refresh failed"
                }
                ok={scanReport.stages.urlhaus.status === "ok"}
              />
              <ScanRow
                label="file integrity (FIM)"
                detail={`${scanReport.stages.fim.baselined_paths} paths baselined · ${scanReport.stages.fim.new_findings} new findings`}
                ok={scanReport.stages.fim.new_findings === 0}
              />
              <ScanRow
                label="canary tokens"
                detail={`${scanReport.stages.canary.planted} decoys planted · ${scanReport.stages.canary.new_findings} touched`}
                ok={scanReport.stages.canary.new_findings === 0}
              />
              <ScanRow
                label="defender event log"
                detail={`${scanReport.stages.defender.new_events} new events since last poll`}
                ok={scanReport.stages.defender.new_events === 0}
              />
              <ScanRow
                label="firewall event log"
                detail={`${scanReport.stages.firewall.new_events} new events since last poll`}
                ok={scanReport.stages.firewall.new_events === 0}
              />
              <div className="border-t border-[color:var(--color-phosphor-faint)] my-2" />
              <div className="text-[color:var(--color-phosphor-dim)]">
                this scan emitted{" "}
                <span className="text-[color:var(--color-phosphor)]">
                  {scanReport.new_events_total}
                </span>{" "}
                new events ({" "}
                <span className="text-[color:var(--color-red)]">{scanReport.new_alerts} alert</span>,{" "}
                <span className="text-[color:var(--color-amber)]">{scanReport.new_warns} warn</span>
                ).
              </div>
              <div className="text-[10px] text-[color:var(--color-phosphor-faint)] mt-2">
                each finding is appended to the merkle audit chain. scroll the event stream below
                to triage individual rows. use [trust fp] / [trust exe] on chrome-style noise to
                quiet future scans.
              </div>
            </div>
          </div>
        </div>
      )}

      {perfReport && <PerfPanel report={perfReport} token={token} onClose={() => setPerfReport(null)} />}
    </main>
  );
}

function ScanRow({ label, detail, ok }: { label: string; detail: string; ok: boolean }) {
  return (
    <div className="flex gap-2 items-baseline">
      <span className={ok ? "text-[color:var(--color-phosphor)]" : "text-[color:var(--color-amber)]"}>
        {ok ? "[ok]" : "[!!]"}
      </span>
      <span className="text-[color:var(--color-phosphor-dim)] w-[170px] shrink-0">{label}</span>
      <span className="text-[color:var(--color-phosphor)]">{detail}</span>
    </div>
  );
}

const PERF_SEV_CLS: Record<string, string> = {
  ok: "text-[color:var(--color-phosphor)] border-[color:var(--color-phosphor)]",
  info: "text-[color:var(--color-phosphor-dim)] border-[color:var(--color-phosphor-faint)]",
  opportunity: "text-[color:var(--color-phosphor)] border-[color:var(--color-phosphor-faint)]",
  warn: "text-[color:var(--color-amber)] border-[color:var(--color-amber)]",
  critical: "text-[color:var(--color-red)] border-[color:var(--color-red)]",
};

const PERF_SEV_RANK: Record<string, number> = {
  critical: 0, warn: 1, opportunity: 2, info: 3, ok: 4,
};

type PerfReportProps = {
  report: {
    elapsed_ms: number;
    host: {
      os_name: string; os_version: string; kernel: string;
      cpu_brand: string; cpu_cores_physical: number; cpu_cores_logical: number;
      mem_total_gb: number; mem_used_gb: number; mem_avail_gb: number;
      uptime_hours: number;
    };
    findings: {
      id: string; category: string; severity: "ok" | "info" | "opportunity" | "warn" | "critical";
      title: string; current: string; recommended: string;
      fix_command: string | null;
      requires_admin: boolean;
    }[];
    gpu: {
      name: string; driver_version: string;
      vram_total_mb: number; vram_used_mb: number; vram_free_mb: number;
      utilization_pct: number; temperature_c: number;
    } | null;
    top_cpu: { pid: number; name: string; cpu_pct: number; mem_mb: number }[];
    top_mem: { pid: number; name: string; cpu_pct: number; mem_mb: number }[];
  };
  token: string;
  onClose: () => void;
};

function PerfPanel({ report, token, onClose }: PerfReportProps) {
  const sorted = [...report.findings].sort(
    (a, b) => (PERF_SEV_RANK[a.severity] ?? 9) - (PERF_SEV_RANK[b.severity] ?? 9)
  );
  return (
    <div
      className="fixed inset-0 bg-black/85 flex items-start justify-center z-50 p-4 overflow-y-auto"
      onClick={onClose}
    >
      <div
        className="box max-w-3xl w-full p-4 bg-black my-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-baseline mb-3">
          <span className="text-[color:var(--color-phosphor)]">// AI / dev workload audit</span>
          <button
            onClick={onClose}
            className="text-[color:var(--color-phosphor-dim)] hover:text-[color:var(--color-phosphor)] text-xs"
          >
            [close]
          </button>
        </div>

        <div className="text-[10px] text-[color:var(--color-phosphor-dim)] mb-3 grid grid-cols-2 gap-x-6 gap-y-0.5 font-mono">
          <div><span className="text-[color:var(--color-phosphor-faint)]">cpu: </span>{report.host.cpu_brand}</div>
          <div><span className="text-[color:var(--color-phosphor-faint)]">cores: </span>{report.host.cpu_cores_physical}p / {report.host.cpu_cores_logical}l</div>
          <div><span className="text-[color:var(--color-phosphor-faint)]">os: </span>{report.host.os_name} {report.host.os_version}</div>
          <div><span className="text-[color:var(--color-phosphor-faint)]">uptime: </span>{report.host.uptime_hours.toFixed(1)} h</div>
          <div><span className="text-[color:var(--color-phosphor-faint)]">ram: </span>{report.host.mem_used_gb.toFixed(1)} / {report.host.mem_total_gb.toFixed(1)} GB used</div>
          <div><span className="text-[color:var(--color-phosphor-faint)]">scan: </span>{report.elapsed_ms} ms</div>
          {report.gpu && (
            <>
              <div className="col-span-2 mt-1 text-[color:var(--color-phosphor)]">
                gpu: {report.gpu.name} · drv {report.gpu.driver_version} · {report.gpu.vram_used_mb}/{report.gpu.vram_total_mb} MB · util {report.gpu.utilization_pct}% · {report.gpu.temperature_c}°C
              </div>
            </>
          )}
        </div>

        <div className="border-t border-[color:var(--color-phosphor-faint)] mb-3" />

        <div className="space-y-2">
          {sorted.map((f, i) => (
            <PerfRow key={`${f.id}-${i}`} f={f} token={token} />
          ))}
        </div>

        <div className="border-t border-[color:var(--color-phosphor-faint)] mt-3 mb-2" />

        <div className="grid grid-cols-2 gap-3 text-[10px] font-mono">
          <div>
            <div className="text-[color:var(--color-phosphor-dim)] mb-1">// top CPU</div>
            {report.top_cpu.map((p) => (
              <div key={`c-${p.pid}`} className="flex gap-2">
                <span className="text-[color:var(--color-phosphor-faint)] w-[40px] tabular-nums text-right">{p.cpu_pct.toFixed(1)}%</span>
                <span className="text-[color:var(--color-phosphor)] truncate">{p.name}</span>
                <span className="text-[color:var(--color-phosphor-faint)] tabular-nums">{p.mem_mb}MB</span>
              </div>
            ))}
          </div>
          <div>
            <div className="text-[color:var(--color-phosphor-dim)] mb-1">// top RAM</div>
            {report.top_mem.map((p) => (
              <div key={`m-${p.pid}`} className="flex gap-2">
                <span className="text-[color:var(--color-phosphor-faint)] w-[60px] tabular-nums text-right">{p.mem_mb}MB</span>
                <span className="text-[color:var(--color-phosphor)] truncate">{p.name}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="text-[10px] text-[color:var(--color-phosphor-faint)] mt-3">
          read-only audit. fixes are not applied automatically — copy any [fix] command and run in
          an elevated PowerShell. severity legend: <span className="text-[color:var(--color-red)]">critical</span> · <span className="text-[color:var(--color-amber)]">warn</span> · opportunity · info · ok.
        </div>
      </div>
    </div>
  );
}

function PerfRow({ f, token }: { f: PerfFinding; token: string }) {
  const [showCmd, setShowCmd] = useState(false);
  const [applying, setApplying] = useState(false);
  const [result, setResult] = useState<PerfApplyOutcome | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const cls = PERF_SEV_CLS[f.severity] ?? PERF_SEV_CLS.info;

  async function performFix() {
    if (!f.fix_command || applying) return;
    const msg = f.requires_admin
      ? `Apply fix: ${f.title}\n\nThis will trigger a Windows UAC prompt for administrator approval.`
      : `Apply fix: ${f.title}\n\nThis will execute the suggested PowerShell command.`;
    if (!confirm(msg)) return;
    setApplying(true);
    setErr(null);
    setResult(null);
    try {
      const res = await fetch("http://127.0.0.1:7878/api/perf/apply", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ fix_command: f.fix_command }),
      });
      if (!res.ok) {
        setErr(`HTTP ${res.status}`);
      } else {
        setResult((await res.json()) as PerfApplyOutcome);
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setApplying(false);
    }
  }

  return (
    <div className="border border-[color:var(--color-phosphor-faint)] p-2 text-xs font-mono">
      <div className="flex gap-2 items-baseline flex-wrap">
        <span className={`px-1 border text-[10px] ${cls}`}>{f.severity}</span>
        <span className="text-[color:var(--color-phosphor-faint)] text-[10px] uppercase">{f.category}</span>
        {f.requires_admin && (
          <span className="px-1 border text-[10px] border-[color:var(--color-amber)] text-[color:var(--color-amber)]">elevate</span>
        )}
        <span className="text-[color:var(--color-phosphor)]">{f.title}</span>
      </div>
      <div className="ml-1 mt-1 text-[color:var(--color-phosphor-dim)] text-[11px]">
        <span className="text-[color:var(--color-phosphor-faint)]">now: </span>{f.current}
      </div>
      <div className="ml-1 text-[color:var(--color-phosphor-dim)] text-[11px]">
        <span className="text-[color:var(--color-phosphor-faint)]">recommend: </span>{f.recommended}
      </div>
      {f.fix_command && (
        <div className="mt-1 ml-1">
          <button
            onClick={() => setShowCmd((v) => !v)}
            className="text-[10px] px-1 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:bg-[rgba(0,255,102,0.06)]"
          >
            {showCmd ? "[hide fix]" : "[show fix]"}
          </button>
          <button
            onClick={performFix}
            disabled={applying}
            className="ml-2 text-[10px] px-1 border border-[color:var(--color-amber)] text-[color:var(--color-amber)] hover:bg-[rgba(255,176,0,0.08)] disabled:opacity-50"
          >
            {applying ? "[applying...]" : "[perform fix]"}
          </button>
          {showCmd && (
            <>
              <button
                onClick={() => { navigator.clipboard.writeText(f.fix_command!); }}
                className="ml-2 text-[10px] px-1 border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor-dim)] hover:bg-[rgba(0,255,102,0.06)]"
              >
                [copy]
              </button>
              <pre className="mt-1 p-2 bg-[rgba(0,255,102,0.04)] border border-[color:var(--color-phosphor-faint)] text-[10px] text-[color:var(--color-phosphor)] whitespace-pre-wrap break-all overflow-x-auto">
{f.fix_command}
              </pre>
            </>
          )}
          {err && (
            <div className="mt-1 text-[10px] text-[color:var(--color-red)]">apply failed: {err}</div>
          )}
          {result && (
            <div className="mt-1 text-[10px]">
              <div className="flex gap-2 items-baseline flex-wrap">
                <span className={`px-1 border ${result.ok ? "border-[color:var(--color-phosphor)] text-[color:var(--color-phosphor)]" : "border-[color:var(--color-red)] text-[color:var(--color-red)]"}`}>
                  {result.ok ? "[ok]" : "[fail]"}
                </span>
                {result.launched_elevated && (
                  <span className="px-1 border border-[color:var(--color-amber)] text-[color:var(--color-amber)]">UAC prompted</span>
                )}
                {result.exit_code !== null && (
                  <span className="text-[color:var(--color-phosphor-faint)]">exit {result.exit_code}</span>
                )}
                <span className="text-[color:var(--color-phosphor-dim)]">{result.message}</span>
              </div>
              {(result.stdout?.trim() || result.stderr?.trim()) && (
                <pre className="mt-1 p-2 bg-[rgba(0,255,102,0.04)] border border-[color:var(--color-phosphor-faint)] text-[color:var(--color-phosphor)] whitespace-pre-wrap break-all overflow-x-auto max-h-48">
{result.stdout?.trim() ? `stdout:\n${result.stdout.trim()}\n` : ""}{result.stderr?.trim() ? `stderr:\n${result.stderr.trim()}` : ""}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
