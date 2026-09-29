import { useEffect, useState } from 'react'
import { AlertOctagon, Download, FileText, Hammer, Undo2 } from 'lucide-react'
import api from '../api.js'

export default function LegalPanel({ refreshKey }) {
  const [ledger, setLedger] = useState(null)
  const [verify, setVerify] = useState(null)
  const [actors, setActors] = useState([])
  const [selected, setSelected] = useState('')
  const [tamperIndex, setTamperIndex] = useState(0)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  async function load() {
    try {
      const [l, v, a] = await Promise.all([api.auditLedger(60), api.auditVerify(), api.actors()])
      setLedger(l)
      setVerify(v)
      setActors(a.actors ?? [])
      if (!selected && a.actors?.length) setSelected(a.actors[0].handle)
    } catch (err) {
      setError(String(err.message ?? err))
    }
  }

  useEffect(() => {
    load()
  }, [refreshKey])

  async function tamper() {
    setError('')
    setMessage('')
    try {
      const res = await api.auditTamper(Number(tamperIndex))
      setMessage(res.message)
      await load()
    } catch (err) {
      setError(String(err.message ?? err))
    }
  }

  async function restore() {
    setError('')
    setMessage('')
    try {
      const res = await api.auditRestore(Number(tamperIndex))
      setMessage(res.restored ? `Block #${res.block_index} restored; ledger verified again.` : 'Nothing to restore.')
      await load()
    } catch (err) {
      setError(String(err.message ?? err))
    }
  }

  const tampered = verify && !verify.verified

  return (
    <div className="space-y-6">
      <div className={`rounded-lg border p-4 ${tampered ? 'animate-flash-red border-rose-700' : 'border-emerald-900 bg-emerald-950/30'}`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400">Merkle ledger state</div>
            <div className={`text-lg font-bold ${tampered ? 'text-white' : 'text-emerald-300'}`}>
              {tampered
                ? `CRITICAL: HASH MISMATCH AT BLOCK #${verify.corrupted_block_index}`
                : `VERIFIED // head #${verify?.head_index ?? '—'} // ${verify?.total_blocks ?? 0} blocks`}
            </div>
          </div>
          <div className="mono max-w-[24rem] truncate text-xs text-slate-400" title={verify?.head_hash}>
            root: {verify?.head_hash?.slice(0, 40) ?? '—'}…
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div>
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">Tamper demonstration</h3>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="number"
              min="0"
              className="mono w-24 rounded border border-slate-800 bg-slate-900 px-2 py-1.5 text-sm"
              value={tamperIndex}
              onChange={(e) => setTamperIndex(e.target.value)}
            />
            <button
              className="flex items-center gap-1.5 rounded bg-rose-800 px-4 py-1.5 text-sm font-semibold hover:bg-rose-700"
              onClick={tamper}
            >
              <Hammer className="h-4 w-4" /> Simulate Database Tamper
            </button>
            <button
              className="flex items-center gap-1.5 rounded bg-slate-800 px-4 py-1.5 text-sm hover:bg-slate-700"
              onClick={restore}
            >
              <Undo2 className="h-4 w-4" /> Restore
            </button>
          </div>
          {message && <p className="mt-2 text-xs text-amber-300">{message}</p>}
          {error && <p className="mt-2 text-xs text-rose-400">{error}</p>}

          <h3 className="mb-2 mt-6 text-sm font-semibold uppercase tracking-wider text-slate-400">Exports</h3>
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="mono rounded border border-slate-800 bg-slate-900 px-2 py-1.5 text-sm"
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
            >
              {actors.length === 0 && <option value="">no actors yet</option>}
              {actors.map((a) => (
                <option key={a.handle} value={a.handle}>
                  @{a.handle}
                </option>
              ))}
            </select>
            <a
              href={selected ? api.dossierUrl(selected) : '#'}
              className={`flex items-center gap-1.5 rounded bg-cyan-700 px-4 py-1.5 text-sm font-semibold hover:bg-cyan-600 ${selected ? '' : 'pointer-events-none opacity-40'}`}
            >
              <FileText className="h-4 w-4" /> Download Section 65B PDF Dossier
            </a>
            <a
              href={selected ? api.stixUrl(selected) : '#'}
              className={`flex items-center gap-1.5 rounded bg-violet-800 px-4 py-1.5 text-sm font-semibold hover:bg-violet-700 ${selected ? '' : 'pointer-events-none opacity-40'}`}
            >
              <Download className="h-4 w-4" /> Export STIX 2.1 Bundle
            </a>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            The PDF is generated server-side with ReportLab and embeds the ledger root,
            chain-of-custody table and a formal Section 65B (BSA 2023) certificate.
          </p>
        </div>

        <div>
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">Merkle block explorer</h3>
          <div className="mono max-h-96 space-y-1.5 overflow-y-auto pr-1 text-xs">
            {(ledger?.blocks ?? []).slice().reverse().map((b) => (
              <div
                key={b.block_index}
                className={`rounded border p-2 ${
                  b.tampered
                    ? 'border-rose-800 bg-rose-950/50'
                    : 'border-slate-800 bg-slate-900/60'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-cyan-400">#{b.block_index}</span>
                  {b.tampered && (
                    <span className="flex items-center gap-1 text-rose-400">
                      <AlertOctagon className="h-3 w-3" /> tampered
                    </span>
                  )}
                  <span className="text-slate-500">{b.timestamp?.slice(0, 19).replace('T', ' ')}</span>
                </div>
                <div className="mt-1 truncate text-slate-400" title={b.current_hash}>
                  {b.current_hash}
                </div>
                <div className="text-slate-600">{b.payload_length} bytes · {b.source_url || 'no source'}</div>
              </div>
            ))}
            {(ledger?.blocks ?? []).length === 0 && (
              <div className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-slate-500">
                Ledger is empty - ingest evidence first.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
