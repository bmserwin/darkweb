import { useState } from 'react'
import { AlertTriangle, Radar, ShieldCheck } from 'lucide-react'
import api from '../api.js'

const DEFAULT_TARGET = 'http://vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion:8443'

const SEVERITY_STYLES = {
  CRITICAL: 'border-rose-800 bg-rose-950/50 text-rose-300',
  HIGH: 'border-orange-800 bg-orange-950/50 text-orange-300',
  MEDIUM: 'border-amber-800 bg-amber-950/50 text-amber-300',
  INFO: 'border-slate-800 bg-slate-900/60 text-slate-300',
}

export default function InfraPanel() {
  const [target, setTarget] = useState(DEFAULT_TARGET)
  const [scan, setScan] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    setError('')
    setScan(null)
    try {
      const data = await api.infraScan(target)
      setScan(data)
    } catch (err) {
      setError(String(err.message ?? err))
    } finally {
      setBusy(false)
    }
  }

  const terminalLines = scan
    ? [
        `$ probe --target ${scan.target}`,
        `route: reserved-lab-suffix -> dialed on loopback (offline testbed)`,
        `tls handshake: ${scan.reachable ? 'OK' : 'FAILED'} / probes: ${scan.findings.length} finding(s)`,
        ...scan.errors.map((e) => `error: ${e}`),
        ...scan.findings.map((f) => `finding [${f.severity}] ${f.finding_type}: ${f.detail}`),
        scan.findings.length === 0 && !scan.errors.length ? 'no findings - target looks clean' : '',
      ].filter(Boolean)
    : []

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <input
          className="mono min-w-[24rem] flex-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-sm"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://<onion>.onion or clearnet staging host"
        />
        <button
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
          onClick={run}
          disabled={busy}
        >
          <Radar className="h-4 w-4" />
          {busy ? 'Probing...' : 'Scan Over Tor (offline testbed)'}
        </button>
      </div>

      {error && <div className="rounded-lg border border-rose-900 bg-rose-950/60 p-3 text-sm text-rose-300">{error}</div>}

      {scan && (
        <div className="grid gap-6 lg:grid-cols-2">
          <div>
            <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">Probe transcript</h3>
            <pre className="mono h-72 overflow-auto rounded-lg border border-slate-800 bg-black/70 p-3 text-xs leading-5 text-emerald-400">
              {terminalLines.join('\n')}
            </pre>
            <div className="mt-3 flex items-center gap-2 text-sm">
              <ShieldCheck className={`h-4 w-4 ${scan.reachable ? 'text-emerald-400' : 'text-slate-500'}`} />
              <span className="text-slate-400">
                Reachable: <b>{scan.reachable ? 'yes' : 'no'}</b> · Composite confidence:{' '}
                <b className="text-amber-400">{(scan.score * 100).toFixed(0)}%</b>
              </span>
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Findings</h3>
            {scan.findings.map((f, i) => (
              <div key={i} className={`rounded-lg border p-3 ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.INFO}`}>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm font-semibold">
                    <AlertTriangle className="h-4 w-4" />
                    {f.title}
                  </span>
                  <span className="mono text-xs">{(f.confidence * 100).toFixed(0)}%</span>
                </div>
                <p className="mt-1 text-xs opacity-90">{f.detail}</p>
              </div>
            ))}
            {scan.findings.length === 0 && (
              <div className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">
                No misconfigurations found for this target.
              </div>
            )}
          </div>
        </div>
      )}

      {!scan && !error && (
        <div className="rounded-lg border border-dashed border-slate-800 p-10 text-center text-sm text-slate-500">
          Enter a target and run a passive probe. The prober never leaves this machine:
          .onion and fixture names resolve against the local simulation containers.
        </div>
      )}
    </div>
  )
}
