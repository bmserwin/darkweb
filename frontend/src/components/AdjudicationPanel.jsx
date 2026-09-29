import { useEffect, useState } from 'react'
import { BadgeCheck, ShieldAlert, ThumbsDown, ThumbsUp } from 'lucide-react'
import api from '../api.js'

const SIGNAL_LABELS = {
  crypto_score: 'Keys / UTXO',
  infra_score: 'Infra',
  temporal_score: 'Circadian',
  stylometry_score: 'Stylometry',
}

function SignalBadge({ name, score, evaluated }) {
  if (!evaluated) {
    return (
      <span className="mono rounded border border-slate-800 bg-slate-900 px-2 py-0.5 text-[11px] text-slate-500">
        {SIGNAL_LABELS[name] ?? name}: n/a
      </span>
    )
  }
  const pct = Math.round((score ?? 0) * 100)
  const tone =
    pct >= 70 ? 'border-emerald-800 bg-emerald-950/60 text-emerald-300'
    : pct >= 40 ? 'border-amber-800 bg-amber-950/60 text-amber-300'
    : 'border-rose-800 bg-rose-950/60 text-rose-300'
  return (
    <span className={`mono rounded border px-2 py-0.5 text-[11px] ${tone}`}>
      {SIGNAL_LABELS[name] ?? name}: {pct}%
    </span>
  )
}

export default function AdjudicationPanel({ refreshKey }) {
  const [queue, setQueue] = useState([])
  const [notes, setNotes] = useState({})
  const [error, setError] = useState('')
  const [busyId, setBusyId] = useState(null)

  async function load() {
    try {
      const data = await api.adjudicationQueue()
      setQueue(data.queue ?? [])
    } catch (err) {
      setError(String(err.message ?? err))
    }
  }

  useEffect(() => {
    load()
  }, [refreshKey])

  async function act(candidateId, action) {
    setBusyId(candidateId)
    setError('')
    try {
      await api.adjudicationAction(candidateId, action, notes[candidateId] ?? '')
      await load()
    } catch (err) {
      setError(String(err.message ?? err))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="space-y-4">
      {error && <div className="rounded-lg border border-rose-900 bg-rose-950/60 p-3 text-sm text-rose-300">{error}</div>}

      {queue.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-800 p-10 text-center text-sm text-slate-500">
          No provisional matches pending. Ingest evidence for at least two actors to generate
          fusion candidates.
        </div>
      )}

      {queue.map((c) => (
        <div key={c.candidate_id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <BadgeCheck className="h-5 w-5 text-cyan-400" />
              <span className="font-semibold">
                {c.source_actor} <span className="text-slate-500">↔</span> {c.target_actor}
              </span>
              <span
                className={`mono rounded px-2 py-0.5 text-xs font-bold ${
                  c.confidence >= 0.7
                    ? 'bg-emerald-950 text-emerald-300'
                    : c.confidence >= 0.4
                      ? 'bg-amber-950 text-amber-300'
                      : 'bg-rose-950 text-rose-300'
                }`}
              >
                {(c.confidence * 100).toFixed(1)}% confidence
              </span>
            </div>
            <div className="flex items-center gap-2">
              <input
                className="w-56 rounded border border-slate-800 bg-slate-950 px-2 py-1.5 text-xs"
                placeholder="Analyst notes (optional)"
                value={notes[c.candidate_id] ?? ''}
                onChange={(e) => setNotes({ ...notes, [c.candidate_id]: e.target.value })}
              />
              <button
                className="flex items-center gap-1 rounded bg-emerald-700 px-3 py-1.5 text-xs font-semibold hover:bg-emerald-600 disabled:opacity-50"
                onClick={() => act(c.candidate_id, 'APPROVE')}
                disabled={busyId === c.candidate_id}
              >
                <ThumbsUp className="h-3.5 w-3.5" /> Approve & Merge
              </button>
              <button
                className="flex items-center gap-1 rounded bg-rose-800 px-3 py-1.5 text-xs font-semibold hover:bg-rose-700 disabled:opacity-50"
                onClick={() => act(c.candidate_id, 'REJECT')}
                disabled={busyId === c.candidate_id}
              >
                <ThumbsDown className="h-3.5 w-3.5" /> Reject Match
              </button>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            {Object.entries(SIGNAL_LABELS).map(([key]) => {
              const signals = c.signals?.signals ?? {}
              const evaluated = (c.signals?.available_signals ?? []).includes(key.replace('_score', ''))
              return (
                <SignalBadge key={key} name={key} score={signals[key]} evaluated={evaluated} />
              )
            })}
          </div>

          {c.contradiction && (
            <div className="mt-3 rounded-lg border border-amber-700 bg-amber-950/60 p-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-amber-300">
                <ShieldAlert className="h-4 w-4" />
                OPSEC Anomaly: Conflicting Evidence Detected
              </div>
              <ul className="mt-1 list-disc pl-5 text-xs text-amber-200/90">
                {(c.contradiction_reasons ?? []).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
