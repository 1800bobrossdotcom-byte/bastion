import AccessGateClient from "./wallet-access-client";

const MATRIX = [
  {
    trait: "Open source codebase",
    bastion: "yes",
    mcafee: "no",
    norton: "no",
    defender: "partial",
  },
  {
    trait: "No required cloud account",
    bastion: "yes",
    mcafee: "no",
    norton: "no",
    defender: "yes",
  },
  {
    trait: "Tamper-evident event chain",
    bastion: "yes",
    mcafee: "no",
    norton: "no",
    defender: "no",
  },
  {
    trait: "Local-first operation on 127.0.0.1",
    bastion: "yes",
    mcafee: "no",
    norton: "no",
    defender: "partial",
  },
  {
    trait: "Readable forensic receipts",
    bastion: "yes",
    mcafee: "no",
    norton: "no",
    defender: "partial",
  },
];

export default function LandingPage() {
  return (
    <main className="min-h-dvh px-4 py-8 max-w-6xl mx-auto text-sm leading-relaxed">
      <section className="panel mb-10 p-5 sm:p-7 overflow-hidden">
        <div className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr] items-start">
          <div>
            <div className="text-[11px] tracking-[0.22em] uppercase text-[color:var(--color-ice)] mb-3">
              Bastion // Local Defensive Sensor
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
              <a href="https://github.com/1800bobrossdotcom/bastion/releases/latest" className="btn-ghost">Download Windows x64</a>
              <a href="https://github.com/1800bobrossdotcom/bastion" className="btn-ghost">Source</a>
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
        <p className="text-[color:var(--color-ice-dim)] mb-4">
          Directional comparison of default product behavior. Not every enterprise add-on is represented.
        </p>
        <table className="w-full min-w-[720px] text-xs border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--color-line)] text-[color:var(--color-ice)]">
              <th className="text-left py-2 pr-3">Trait</th>
              <th className="text-left py-2 pr-3">Bastion</th>
              <th className="text-left py-2 pr-3">McAfee</th>
              <th className="text-left py-2 pr-3">Norton</th>
              <th className="text-left py-2">Defender</th>
            </tr>
          </thead>
          <tbody>
            {MATRIX.map((row) => (
              <tr key={row.trait} className="border-b border-[color:var(--color-line-soft)] text-[color:var(--color-ice-dim)]">
                <td className="py-2 pr-3 text-[color:var(--color-ice)]">{row.trait}</td>
                <td className="py-2 pr-3 text-[color:var(--color-phosphor)]">{row.bastion}</td>
                <td className="py-2 pr-3">{row.mcafee}</td>
                <td className="py-2 pr-3">{row.norton}</td>
                <td className="py-2">{row.defender}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
