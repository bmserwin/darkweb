import { useCallback, useEffect, useState } from 'react'
import { Activity, ShieldCheck, ShieldX } from 'lucide-react'
import IngestionPanel from './components/IngestionPanel.jsx'
import InfraPanel from './components/InfraPanel.jsx'
import GraphPanel from './components/GraphPanel.jsx'
import AdjudicationPanel from './components/AdjudicationPanel.jsx'
import LegalPanel from './components/LegalPanel.jsx'
import api from './api.js'

const TABS = [
  { id: 'ingest', label: '1. Triage & Ingestion' },
  { id: 'infra', label: '2. Infrastructure Scanner' },
  { id: 'graph', label: '3. Temporal Knowledge Graph' },
  { id: 'adjudication', label: '4. Adjudication Console' },
  { id: 'legal', label: '5. Legal Audit & Dossier' },
]

export default function App() {
  const [tab, setTab] = useState('ingest')
  const [health, setHealth] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)

  const refreshHealth = useCallback(async () => {
    try {
      setHealth(await api.health())
    } catch {
      setHealth(null)
    }
  }, [])

  useEffect(() => {
    refreshHealth()
    const timer = setInterval(refreshHealth, 15000)
    return () => clearInterval(timer)
  }, [refreshHealth])

  const verified = health?.ledger?.verified
  const online = Boolean(health)

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-6 py-3">
          <h1 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            Evidence-First Forensic Platform
          </h1>
          <div className="flex items-center gap-3 text-xs">
            <span className={`flex items-center gap-1.5 rounded-full px-3 py-1 font-semibold ${
              online ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'
            }`}>
              <Activity className="h-3.5 w-3.5" />
              {online ? 'System Online' : 'Backend Offline'}
            </span>
            <span className={`flex items-center gap-1.5 rounded-full px-3 py-1 font-semibold ${
              verified ? 'bg-emerald-950 text-emerald-400' : 'animate-flash-red text-white'
            }`}>
              {verified ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldX className="h-3.5 w-3.5" />}
              {verified ? 'Ledger Verified' : health ? 'LEDGER TAMPERED' : 'Ledger Unknown'}
            </span>
            <span className="mono hidden rounded-full bg-slate-900 px-3 py-1 text-slate-400 md:inline">
              {health?.case_reference ?? 'CASE-—'}
            </span>
          </div>
        </div>
        <nav className="mx-auto flex max-w-7xl gap-1 overflow-x-auto px-4">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`whitespace-nowrap rounded-t-lg px-4 py-2 text-sm font-medium transition ${
                tab === t.id
                  ? 'border-x border-t border-slate-800 bg-slate-900 text-cyan-400'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-6">
        {tab === 'ingest' && <IngestionPanel onIngested={() => { setRefreshKey((k) => k + 1); refreshHealth() }} />}
        {tab === 'infra' && <InfraPanel />}
        {tab === 'graph' && <GraphPanel refreshKey={refreshKey} />}
        {tab === 'adjudication' && <AdjudicationPanel refreshKey={refreshKey} />}
        {tab === 'legal' && <LegalPanel refreshKey={refreshKey} />}
      </main>
    </div>
  )
}
