import AccessGateClient from "./wallet-access-client";
import BastionMark from "@/components/BastionMark";

const MATRIX = [
  { trait: "Open source codebase",                             bastion: "yes",     mcafee: "no",      norton: "no",      defender: "partial", crowdstrike: "no",      sentinelone: "no",      malwarebytes: "no",      huntress: "no" },
  { trait: "No required cloud account",                        bastion: "yes",     mcafee: "no",      norton: "no",      defender: "yes",     crowdstrike: "no",      sentinelone: "no",      malwarebytes: "no",      huntress: "no" },
  { trait: "Tamper-evident merkle event chain",                bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "partial", sentinelone: "partial", malwarebytes: "no",      huntress: "no" },
  { trait: "Local-first operation on 127.0.0.1",               bastion: "yes",     mcafee: "no",      norton: "no",      defender: "partial", crowdstrike: "no",      sentinelone: "no",      malwarebytes: "yes",     huntress: "no" },
  { trait: "Human-readable forensic receipts",                 bastion: "yes",     mcafee: "no",      norton: "no",      defender: "partial", crowdstrike: "partial", sentinelone: "partial", malwarebytes: "no",      huntress: "partial" },
  { trait: "File integrity monitor on system paths",           bastion: "yes",     mcafee: "partial", norton: "partial", defender: "partial", crowdstrike: "yes",     sentinelone: "yes",     malwarebytes: "no",      huntress: "partial" },
  { trait: "Canary / decoy token detection",                   bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "yes",     sentinelone: "yes",     malwarebytes: "no",      huntress: "yes" },
  { trait: "Per-process kill / quarantine from one UI",        bastion: "yes",     mcafee: "yes",     norton: "yes",     defender: "yes",     crowdstrike: "yes",     sentinelone: "yes",     malwarebytes: "yes",     huntress: "partial" },
  { trait: "Reversible quarantine vault (audited)",            bastion: "yes",     mcafee: "partial", norton: "partial", defender: "yes",     crowdstrike: "yes",     sentinelone: "yes",     malwarebytes: "yes",     huntress: "no" },
  { trait: "URLhaus / OpenPhish DNS blocklist refresh",        bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "no",      sentinelone: "no",      malwarebytes: "partial", huntress: "no" },
  { trait: "Process fingerprint + lineage tracking",           bastion: "yes",     mcafee: "no",      norton: "no",      defender: "partial", crowdstrike: "yes",     sentinelone: "yes",     malwarebytes: "no",      huntress: "partial" },
  { trait: "Autoruns / persistence drift surfacing",           bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "yes",     sentinelone: "yes",     malwarebytes: "no",      huntress: "yes" },
  { trait: "Camera / mic access surveillance log",             bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "no",      sentinelone: "no",      malwarebytes: "no",      huntress: "no" },
  { trait: "Microsoft Sentinel ingest bridge",                 bastion: "yes",     mcafee: "no",      norton: "no",      defender: "n/a",     crowdstrike: "yes",     sentinelone: "yes",     malwarebytes: "no",      huntress: "yes" },
  { trait: "Per-event WHY explanation (LLM-optional)",         bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "partial", sentinelone: "partial", malwarebytes: "no",      huntress: "partial" },
  { trait: "Performance audit (power plan / GPU / RAM)",       bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "no",      sentinelone: "no",      malwarebytes: "no",      huntress: "no" },
  { trait: "Donation-based pricing",                           bastion: "yes",     mcafee: "no",      norton: "no",      defender: "n/a",     crowdstrike: "no",      sentinelone: "no",      malwarebytes: "no",      huntress: "no" },
  { trait: "No telemetry shipped off-device",                  bastion: "yes",     mcafee: "no",      norton: "no",      defender: "no",      crowdstrike: "no",      sentinelone: "no",      malwarebytes: "no",      huntress: "no" },
];

const VENDOR_COLS = [
  { key: "bastion",      label: "Bastion",      highlight: true },
  { key: "defender",     label: "Defender" },
  { key: "mcafee",       label: "McAfee" },
  { key: "norton",       label: "Norton" },
  { key: "malwarebytes", label: "Malwarebytes" },
  { key: "huntress",     label: "Huntress" },
  { key: "crowdstrike",  label: "CrowdStrike" },
  { key: "sentinelone",  label: "SentinelOne" },
];

const CELL_CLASS: Record<string, string> = {
  yes:     "text-[color:var(--color-phosphor)]",
  partial: "text-[color:var(--color-amber)]",
  no:      "text-[color:var(--color-ice-dim)]",
  "n/a":   "text-[color:var(--color-ice-dim)] opacity-60",
};

// Checklist: what Bastion v0.2 actually does on your machine, grouped so a
// reader can audit the marketing copy against the code in /agent/src.
const CHECKLIST: { group: string; items: { label: string; status: "shipped" | "partial" | "roadmap"; note?: string }[] }[] = [
  {
    group: "Sensing (read-only)",
    items: [
      { label: "Recent process tree (proc_fp) with novel-fingerprint flagging", status: "shipped" },
      { label: "Network indicator blocklist (URLhaus + OpenPhish, refreshed in background)", status: "shipped" },
      { label: "File integrity monitor on Windows system paths + hosts file", status: "shipped" },
      { label: "Canary / decoy tokens planted, watched for tamper", status: "shipped" },
      { label: "Microsoft Defender event ingest (event log poll)", status: "shipped" },
      { label: "Windows Firewall rule-change ingest", status: "shipped" },
      { label: "Autoruns / persistence (Run keys, services, scheduled tasks)", status: "shipped" },
      { label: "Camera / mic access enumeration (privacy registry log)", status: "shipped" },
      { label: "DGA-style hostname heuristic on outbound DNS", status: "shipped" },
      { label: "MalwareBazaar SHA256 hashlist scan-on-write", status: "shipped" },
    ],
  },
  {
    group: "Recording & integrity",
    items: [
      { label: "Append-only event store (sqlite)", status: "shipped" },
      { label: "Merkle audit chain over every event row (tamper-evident)", status: "shipped" },
      { label: "Boot integrity rollup before steady-state detectors", status: "shipped" },
      { label: "Local DPAPI-sealed secrets storage", status: "shipped", note: "Windows only" },
      { label: "Forensic export bundle (signed zip)", status: "shipped" },
    ],
  },
  {
    group: "Response (operator action)",
    items: [
      { label: "Kill PID with audited reason", status: "shipped" },
      { label: "Quarantine to reversible vault (sha256 + original path receipt)", status: "shipped" },
      { label: "Trust a fingerprint or a whole exe (suppresses future noise)", status: "shipped" },
      { label: "Resolve / re-open per-event triage state", status: "shipped" },
      { label: "Run full scan on demand", status: "shipped" },
      { label: "Performance audit + elevated apply for safe recommendations", status: "shipped" },
    ],
  },  {
    group: "Bridges",
    items: [
      { label: "Microsoft Sentinel incident pull (azure-cli auth)", status: "shipped" },
      { label: "ntfy.sh push notifications (optional)", status: "shipped" },
      { label: "Windows toast notifier on alerts", status: "shipped" },
      { label: "Webhook ingest for arbitrary upstream SIEMs", status: "partial", note: "Sentinel-shaped only today" },
    ],
  },
  {
    group: "UI",
    items: [
      { label: "Severity counters (ALERT/WARN/INFO) clickable to filter", status: "shipped" },
      { label: "Hide-noise toggle + risk classification chip on each row", status: "shipped" },
      { label: "Per-event WHY explanation (causal chain + AI manager)", status: "shipped" },
      { label: "Quarantine vault list + reversible restore", status: "shipped" },
      { label: "Source filter chips (proc_fp / autoruns / camera_mic / …)", status: "shipped" },
    ],
  },
  {
    group: "Roadmap (next updates)",
    items: [
      { label: "Real-time on-access file scanning (ETW + AMSI provider) — detect & respond without a kernel driver", status: "partial", note: "in design" },
      { label: "On-access kernel minifilter driver (blocks malicious writes pre-execution; Azure Trusted Signing)", status: "roadmap" },
      { label: "Persist resolve / triage state to agent DB (durable across reboots)", status: "shipped" },
      { label: "Restore-from-vault button + sha256 verify on restore", status: "roadmap" },
      { label: "Generic webhook ingest schema (Splunk / Elastic / Wazuh)", status: "roadmap" },
      { label: "Sigma rule loader for custom detections", status: "roadmap" },
      { label: "macOS launchd + EndpointSecurity port of the agent", status: "roadmap" },
      { label: "Linux auditd + inotify port of the agent", status: "roadmap" },
      { label: "Signed release artifacts (cosign + SLSA provenance)", status: "roadmap" },
      { label: "Optional remote forwarder for multi-host triage", status: "roadmap" },
      { label: "YARA scan integration into quarantine pipeline", status: "roadmap" },
      { label: "Tor / Tailscale-friendly secondary bind", status: "roadmap" },
    ],
  },
];

const STATUS_CLS: Record<"shipped" | "partial" | "roadmap", string> = {
  shipped: "text-[color:var(--color-phosphor)]",
  partial: "text-[color:var(--color-amber)]",
  roadmap: "text-[color:var(--color-ice-dim)]",
};
const STATUS_LBL: Record<"shipped" | "partial" | "roadmap", string> = {
  shipped: "[shipped]",
  partial: "[partial]",
  roadmap: "[roadmap]",
};

// Annotated walkthrough of the actual dashboard so the website's claims map
// 1:1 to UI elements a buyer can verify. Each block describes a real region
// of /app rendered by src/app/app/page.tsx.
const SCREEN_ANNOTATIONS: { region: string; what: string; backed_by: string }[] = [
  {
    region: "Boot banner ([ok] phosphor calibrated …)",
    what: "Five-line ready check. Confirms the local agent on 127.0.0.1:7878 is reachable and that the bearer token has been pasted.",
    backed_by: "BOOT_LINES in dashboard/src/app/app/page.tsx; /api/health in agent/src/api.rs",
  },
  {
    region: "ALERT / WARN / INFO / REMOVED counters",
    what: "Live counts of unresolved events at each severity, plus the count of items the operator has already quarantined or killed. Click any counter to filter the stream to that severity. Click REMOVED to open the vault.",
    backed_by: "counts{} block in app/page.tsx; data from /api/events and /api/quarantine/list",
  },
  {
    region: "Source filter row ([all] [attestation] [autoruns] [camera_mic] [lineage] [proc_fp] [process_net] …)",
    what: "One chip per detector that has emitted at least one event since boot. Pick a chip to narrow the stream to that subsystem.",
    backed_by: "sources = unique(events.source) in app/page.tsx; detectors/ in agent/src",
  },
  {
    region: "[hide noise] / [show resolved] / [resolve N] / [reset triage] toggles",
    what: "Hide-noise hides browser/shell signed-binary churn so only review-worthy rows remain. Resolve marks individual rows as triaged and decrements the counter without ever editing the merkle chain. Reset triage forgets the local resolved markers.",
    backed_by: "assessRisk() in app/page.tsx; triage table + /api/triage routes in agent/src/{store,api}.rs",
  },
  {
    region: "[run full scan]",
    what: "Forces a synchronous sweep: URLhaus refresh, FIM scan, canary verify, Defender + firewall log poll. Returns a per-stage report in a modal.",
    backed_by: "POST /api/scan/run in agent/src/api.rs",
  },
  {
    region: "[perf audit]",
    what: "Reads power plan, GPU, RAM headroom, disk free, Defender exclusions, WSL memory cap, top CPU/RAM consumers. Returns recommendations; safe ones can be applied via elevated PowerShell.",
    backed_by: "GET /api/perf/audit + POST /api/perf/apply in agent/src/api.rs",
  },
  {
    region: "Event row body",
    what: "Timestamp · severity glyph · detector source · risk chip (noise / review / suspicious / critical) · one-line summary, with full JSON details expanded underneath.",
    backed_by: "events list render in app/page.tsx; rows fetched from GET /api/events",
  },
  {
    region: "Per-row response buttons ([kill pid] [quarantine] [trust fp] [trust exe] [why] [resolve])",
    what: "Kill the offending PID, move a file to the reversible vault, suppress a fingerprint, ask the AI manager to explain causality, or mark this row resolved.",
    backed_by: "POST /api/respond/kill-pid + /api/respond/quarantine + /api/trust/* + /api/why/event/:id",
  },
  {
    region: "Chain status (chain ok · N rows · head HASH)",
    what: "Live verification that the merkle audit chain has not been edited. If anything modified the event log out-of-band, the dashboard shows a red [tamper] banner pointing at the broken row id.",
    backed_by: "GET /api/chain/verify in agent/src/api.rs",
  },
  {
    region: "Microsoft Sentinel connector card",
    what: "Optional cloud bridge. If azure-cli is signed in to a tenant + subscription + Log Analytics workspace, pulls Sentinel incidents into the local event stream. Honesty note: this does not run Sentinel for you, and never ships your local events outward.",
    backed_by: "Connectors API in agent/src/api.rs (connectors_list / sentinel_save / sentinel_pull)",
  },
];

const HONESTY = [
  "Bastion is a defensive sensor. It does not block kernel rootkits or nation-state zero-days.",
  "It runs locally and ships nothing to any cloud unless you explicitly configure a bridge (Sentinel, ntfy).",
  "It cannot stop an attacker who already has SYSTEM privileges and can disable services.",
  "The merkle chain is tamper-evident, not tamper-proof: it tells you the log was edited, not that it can't be.",
  "Quarantine is best-effort: locked or in-use originals are copied to vault but may not be removed in place.",
];

export default function LandingPage() {
  return (
    <main className="terminal-theme min-h-dvh px-4 py-8 max-w-6xl mx-auto text-sm leading-relaxed">
      <section className="panel mb-10 p-5 sm:p-7 overflow-hidden">
        <div className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr] items-start">
          <div>
            <div className="flex items-center gap-2 text-[11px] tracking-[0.22em] uppercase text-[color:var(--color-ice)] mb-3">
              <BastionMark size={18} className="text-[color:var(--color-phosphor)]" />
              <span>Bastion // Local Defensive Sensor</span>
            </div>
            <pre className="text-[9px] sm:text-[11px] whitespace-pre overflow-x-auto mb-4 text-[color:var(--color-phosphor)]">{`
 ____    _    ____ _____ ___ ___  _   _
| __ )  / \\  / ___|_   _|_ _/ _ \\| \\ | |
|  _ \\ / _ \\ \\___ \\ | |  | | | | |  \\| |
| |_) / ___ \\ ___) || |  | | |_| | |\\  |
|____/_/   \\_\\____/ |_| |___\\___/|_| \\_|
            `}</pre>
            <h1 className="text-3xl sm:text-5xl font-semibold text-[color:var(--color-phosphor)] leading-[1.1]">
              Detection-first security,
              <br />
              without the black box.
            </h1>
            <p className="mt-4 text-[color:var(--color-ice-dim)] max-w-2xl">
              Bastion is a local Windows sensor with a tamper-evident audit stream, response controls,
              and optional Sentinel pull mode. It is intentionally transparent: you can read what it does,
              verify what it logged, and decide what action to take.
            </p>
            <div className="mt-5 flex flex-wrap gap-3">
              <a href="/app" className="btn-primary">Unlock Console</a>
              <a href="https://github.com/1800bobrossdotcom-byte/bastion/releases/latest" className="btn-ghost">Download Windows x64</a>
              <a href="https://github.com/1800bobrossdotcom-byte/bastion" className="btn-ghost">Source</a>
            </div>
          </div>
          <aside className="panel-subtle p-4 text-xs">
            <div className="text-[color:var(--color-ice)] mb-2 uppercase tracking-[0.16em]">Honesty Scope</div>
            <p className="text-[color:var(--color-ice-dim)] mb-2">
              Bastion surfaces suspicious behavior and gives you receipts. It does not claim magical prevention
              against kernel rootkits or nation-state zero-days.
            </p>
            <p className="text-[color:var(--color-ice-dim)]">
              If you believe you are targeted, escalate to <a className="text-[color:var(--color-phosphor)]" href="https://citizenlab.ca">Citizen Lab</a> or <a className="text-[color:var(--color-phosphor)]" href="https://accessnow.org/help">Access Now</a>.
            </p>
          </aside>
        </div>
      </section>

      <section className="mb-10">
        <div className="mb-4">
          <h2 className="text-xl sm:text-2xl text-[color:var(--color-phosphor)]">Get Access</h2>
          <p className="text-xs text-[color:var(--color-ice-dim)] mt-1">
            Access is donation-based. Enter $0.00 for free — or any amount you wish. Submit and we email your key instantly.
          </p>
        </div>
        <AccessGateClient />
      </section>

      <section className="panel mb-10 p-5 sm:p-6 overflow-x-auto">
        <h2 className="text-xl sm:text-2xl text-[color:var(--color-phosphor)] mb-2">Comparison Snapshot</h2>
        <p className="text-[color:var(--color-ice-dim)] mb-2">
          Directional comparison of default product behavior against eight named endpoint products. Not every enterprise add-on is represented.
        </p>
        <p className="text-[10px] text-[color:var(--color-ice-dim)] mb-4">
          Legend: <span className="text-[color:var(--color-phosphor)]">yes</span> ·{" "}
          <span className="text-[color:var(--color-amber)]">partial</span> ·{" "}
          <span className="opacity-70">no</span> · n/a
        </p>
        <table className="w-full min-w-[920px] text-xs border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--color-line)] text-[color:var(--color-ice)]">
              <th className="text-left py-2 pr-3">Trait</th>
              {VENDOR_COLS.map((v) => (
                <th
                  key={v.key}
                  className={`text-left py-2 pr-3 ${v.highlight ? "text-[color:var(--color-phosphor)]" : ""}`}
                >
                  {v.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MATRIX.map((row) => (
              <tr key={row.trait} className="border-b border-[color:var(--color-line-soft)] text-[color:var(--color-ice-dim)]">
                <td className="py-2 pr-3 text-[color:var(--color-ice)]">{row.trait}</td>
                {VENDOR_COLS.map((v) => {
                  const val = (row as unknown as Record<string, string>)[v.key];
                  return (
                    <td key={v.key} className={`py-2 pr-3 ${CELL_CLASS[val] ?? ""}`}>{val}</td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel mb-10 p-5 sm:p-6">
        <h2 className="text-xl sm:text-2xl text-[color:var(--color-phosphor)] mb-2">What You See When Running</h2>
        <p className="text-[color:var(--color-ice-dim)] mb-4 text-xs">
          A literal walkthrough of the desktop window. Every region listed below maps to a file path so you can audit the
          claim against the code, not just trust the screenshot.
        </p>
        <pre className="text-[10px] sm:text-[11px] leading-tight bg-black/40 border border-[color:var(--color-line)] p-3 overflow-x-auto text-[color:var(--color-phosphor)]">{`
+---------------------------------------------------------------------------+
| [ok] phosphor calibrated    chain ok · 1402 rows · head 8f3a…b2c1         |
+---------------------------------------------------------------------------+
| [ ALERT 003 ]  [ WARN 028 ]  [ INFO 005 ]  [ REMOVED 014 ]                |
+---------------------------------------------------------------------------+
| sources: [all] [attestation] [autoruns] [camera_mic] [proc_fp] [response] |
| toggles: [hide noise: 41] [show resolved: 12] [resolve 7] [reset triage]  |
| actions: [run full scan] [perf audit] [connectors] [export bundle]        |
+---------------------------------------------------------------------------+
| 13:42:07  !  proc_fp        review     unknown.exe pid 9180 (parent: …)   |
|           > [kill pid] [quarantine] [trust fp] [trust exe] [why] [resolve]|
| 13:41:55  ·  camera_mic     info       camera in use by chrome.exe        |
|           > [why] [resolve]                                               |
| 13:41:31  !! autoruns       suspicious new Run key: HKCU\\…\\update.lnk    |
|           > [quarantine] [trust exe] [why] [resolve]                      |
+---------------------------------------------------------------------------+
| chain: ok · last-verified 1s ago    sentinel: linked (workspace: bobops)  |
+---------------------------------------------------------------------------+
`}</pre>
        <ul className="mt-4 grid gap-3 text-xs">
          {SCREEN_ANNOTATIONS.map((a) => (
            <li key={a.region} className="border-l-2 border-[color:var(--color-phosphor-faint)] pl-3">
              <div className="text-[color:var(--color-phosphor)]">{a.region}</div>
              <div className="text-[color:var(--color-ice-dim)]">{a.what}</div>
              <div className="text-[10px] text-[color:var(--color-ice-dim)] opacity-70">backed by: <code>{a.backed_by}</code></div>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel mb-10 p-5 sm:p-6">
        <h2 className="text-xl sm:text-2xl text-[color:var(--color-phosphor)] mb-2">Detection &amp; Response Checklist</h2>
        <p className="text-[color:var(--color-ice-dim)] mb-4 text-xs">
          Every line below is either shipped today, partially implemented, or on the roadmap. Nothing is marketed that the
          agent does not actually do.
        </p>
        <div className="grid gap-5 md:grid-cols-2">
          {CHECKLIST.map((group) => (
            <div key={group.group}>
              <h3 className="text-sm text-[color:var(--color-phosphor)] mb-2">{group.group}</h3>
              <ul className="space-y-1 text-xs">
                {group.items.map((it) => (
                  <li key={it.label} className="flex gap-2">
                    <span className={`shrink-0 ${STATUS_CLS[it.status]}`}>{STATUS_LBL[it.status]}</span>
                    <span className="text-[color:var(--color-ice-dim)]">
                      {it.label}
                      {it.note && <span className="opacity-60"> — {it.note}</span>}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section className="panel mb-10 p-5 sm:p-6">
        <h2 className="text-xl sm:text-2xl text-[color:var(--color-phosphor)] mb-2">Honesty Notes</h2>
        <ul className="space-y-1 text-xs text-[color:var(--color-ice-dim)] list-disc list-inside">
          {HONESTY.map((h) => (
            <li key={h}>{h}</li>
          ))}
        </ul>
      </section>

      <section className="grid gap-4 md:grid-cols-2 mb-10">
        <article className="panel-subtle p-4">
          <h3 className="text-lg text-[color:var(--color-phosphor)] mb-2">Support Development</h3>
          <p className="text-[color:var(--color-ice-dim)] mb-3 text-xs">
            Bastion is free. If it helps you, BTC or ETH donations keep development moving — any amount is welcome.
          </p>
          <div className="space-y-2 text-xs">
            <div className="wallet-row"><strong>BTC:</strong> <code>bc1qtf6fqllw7dny832ksw67p4a99txgvrct7u9e7d</code></div>
            <div className="wallet-row"><strong>ETH:</strong> <code>0x70B666c4e3EE5B2C9Ab92925F097330813D1848a</code></div>
          </div>
        </article>
        <article className="panel-subtle p-4">
          <h3 className="text-lg text-[color:var(--color-phosphor)] mb-2">How Access Works</h3>
          <ol className="space-y-1 text-xs text-[color:var(--color-ice-dim)]">
            <li>1. Enter your email and a USD donation amount ($0.00 = free).</li>
            <li>2. Press <strong className="text-[color:var(--color-phosphor)]">Get Access Key</strong> — we email your signed key immediately.</li>
            <li>3. Open <a href="/app" className="text-[color:var(--color-phosphor)]">/app</a>, paste your key, then paste the agent bearer token from <code>%APPDATA%\bastion\data\token.txt</code>.</li>
            <li>4. If you wish to donate, send BTC or ETH to the addresses above.</li>
          </ol>
        </article>
      </section>

      <footer className="text-[11px] text-[color:var(--color-ice-dim)] border-t border-[color:var(--color-line)] pt-4 pb-2">
        <p>bastion.quest // {new Date().getFullYear()} // local-first defensive sensor</p>
      </footer>
    </main>
  );
}
