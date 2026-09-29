import { useEffect, useState } from 'react'
import { Anchor, Fingerprint, Globe, ShieldAlert, Wallet } from 'lucide-react'
import api from '../api.js'

const SAMPLE = `Vendor post - verified list updated today.
PGP: -----BEGIN PGP PUBLIC KEY BLOCK-----
mQINBGXkFQ0BEADKxT8EXAMPLEBLOCKEXAMPLEBLOCKEXAMPLEBLOCKEXAMPLE
-----END PGP PUBLIC KEY BLOCK-----
BTC: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Mirror: http://vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion
Contact: @darkfox77 - shipping worldwide, escrow accepted.`

function Stat({ icon: Icon, label, value, tone = 'text-cyan-400' }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-3">
      <Icon className={`h-6 w-6 ${tone}`} />
      <div>
        <div className="text-xs uppercase tracking-wider text-slate-500">{label}</div>
        <div className="text-xl font-semibold">{value}</div>
      </div>
    </div>
  )
}

export default function IngestionPanel({ onIngested }) {
  const [text, setText] = useState('')
  const [source, setSource] = useState('http://mock-onion:8080/vendor/darkfox77')
  const [handle, setHandle] = useState('darkfox77')
  const [observations, setObservations] = useState([])
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function refresh() {
    try {
      const data = await api.observations(25)
      setObservations(data.observations ?? [])
    } catch (err) {
      setError(String(err.message ?? err))
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  async function ingest() {
    if (!text.trim()) {
      setError('Nothing to ingest: paste a payload first.')
      return
    }
    setBusy(true)
    setError('')
    setResult(null)
    try {
      const data = await api.ingest({
        text,
        source,
        platform: 'manual',
        actor_handle: handle.trim() || null,
      })
      setResult(data)
      setText('')
      await refresh()
      onIngested?.()
    } catch (err) {
      setError(String(err.message ?? err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat icon={Anchor} label="Anchored blocks" value={observations.length} />
        <Stat icon={Fingerprint} label="Observations" value={observations.length} />
        <Stat icon={Wallet} label="Ledger head" value={observations[0]?.ledger_block ?? '—'} tone="text-amber-400" />
        <Stat icon={ShieldAlert} label="Contradictions" value={observations.filter((o) => o.contradiction).length} tone="text-rose-400" />
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Universal intake</h2>
            <button
              className="text-xs text-cyan-500 hover:text-cyan-300"
              onClick={() => setText(SAMPLE)}
            >
              Load sample payload
            </button>
          </div>
          <textarea
            className="mono h-56 w-full rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm focus:border-cyan-600 focus:outline-none"
            placeholder="Paste raw dark-web dump, vendor post, forum scrape..."
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="flex flex-wrap gap-3">
            <input
              className="mono w-64 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-sm"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder="Source URL / label"
            />
            <input
              className="mono w-44 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-sm"
              value={handle}
              onChange={(e) => setHandle(e.target.value)}
              placeholder="Actor handle (optional)"
            />
            <button
              className="rounded-lg bg-cyan-600 px-5 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
              onClick={ingest}
              disabled={busy}
            >
              {busy ? 'Anchoring...' : 'Ingest & Anchor'}
            </button>
          </div>
          {error && <div className="rounded-lg border border-rose-900 bg-rose-950/60 p-3 text-sm text-rose-300">{error}</div>}
          {result && (
            <div className="rounded-lg border border-emerald-900 bg-emerald-950/40 p-3 text-sm text-emerald-300">
              <div>
                Block #{result.ledger_block} · {result.identifiers.length} identifier(s) extracted
              </div>
              <ul className="mono mt-2 space-y-1 text-xs text-emerald-200/90">
                {result.identifiers.map((id, i) => (
                  <li key={i}>
                    [{id.id_type}] {String(id.value).slice(0, 70)}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Recent captures</h2>
          <div className="max-h-[30rem] space-y-2 overflow-y-auto pr-1">
            {observations.map((o) => (
              <div key={o.observation_id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <div className="flex items-center justify-between text-xs text-slate-500">
                  <span className="mono text-cyan-400">#{o.ledger_block}</span>
                  <span>{o.observed_at?.slice(0, 19).replace('T', ' ')}</span>
                </div>
                <div className="mono mt-1 truncate text-xs text-slate-400" title={o.source_url}>
                  <Globe className="mr-1 inline h-3 w-3" />
                  {o.source_url}
                </div>
                <p className="mt-1 line-clamp-2 text-xs text-slate-300">{o.payload_preview}</p>
              </div>
            ))}
            {observations.length === 0 && (
              <div className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">
                No evidence anchored yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
