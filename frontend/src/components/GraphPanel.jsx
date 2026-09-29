import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Clock, Loader2 } from 'lucide-react'
import api from '../api.js'

const COLORS = {
  actor: '#38bdf8', // blue - persona
  btc: '#facc15', // yellow - wallet
  pgp: '#fb923c', // orange - PGP
  ip: '#f87171', // red - clearnet IP
  onion: '#c084fc', // purple - onion
  handle: '#2dd4bf', // teal - handle
  identifier: '#94a3b8',
}

function nodeColor(node) {
  if (node.type === 'actor') return COLORS.actor
  if (node.detail?.contradiction) return '#f43f5e'
  return COLORS[node.group?.toLowerCase()] ?? COLORS.identifier
}

function nodeLabel(node) {
  return `${node.type === 'actor' ? '@' : ''}${node.label}`
}

export default function GraphPanel({ refreshKey }) {
  const [snapshot, setSnapshot] = useState(null)
  const [cutoff, setCutoff] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const containerRef = useRef(null)
  const [dimensions, setDimensions] = useState({ width: 900, height: 520 })

  useEffect(() => {
    const update = () => {
      const el = containerRef.current
      if (el) setDimensions({ width: el.clientWidth, height: 520 })
    }
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [])

  async function load(cutoffTime) {
    setLoading(true)
    setError('')
    try {
      const data = await api.graph(cutoffTime || null)
      setSnapshot(data)
    } catch (err) {
      setError(String(err.message ?? err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load(cutoff)
  }, [refreshKey])

  // Debounced cutoff changes keep the scrubber smooth while dragging.
  useEffect(() => {
    const t = setTimeout(() => load(cutoff), 350)
    return () => clearTimeout(t)
  }, [cutoff])

  const graphData = useMemo(() => {
    if (!snapshot) return { nodes: [], links: [] }
    return {
      nodes: snapshot.nodes.map((n) => ({ ...n, val: n.type === 'actor' ? 6 : 3 })),
      links: snapshot.links.map((l) => ({ ...l })),
    }
  }, [snapshot])

  const stats = snapshot?.stats ?? {}

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4 rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <Clock className="h-5 w-5 text-cyan-400" />
        <span className="text-xs uppercase tracking-wider text-slate-400">Time scrubber</span>
        <input
          type="range"
          min="0"
          max="100"
          defaultValue="100"
          className="h-1 flex-1 cursor-pointer accent-cyan-500"
          onChange={(e) => {
            const pct = Number(e.target.value)
            if (pct >= 100) {
              setCutoff('')
              return
            }
            // Map the slider onto 2022-01-01 .. now.
            const start = Date.UTC(2022, 0, 1)
            const end = Date.now()
            const picked = new Date(start + ((end - start) * pct) / 100)
            setCutoff(picked.toISOString())
          }}
        />
        <span className="mono w-56 text-right text-xs text-slate-400">
          {cutoff ? `view @ ${cutoff.slice(0, 16).replace('T', ' ')}Z` : 'view @ live state'}
        </span>
        <span className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Nodes</span>
          <b>{stats.node_count ?? '—'}</b>
          <span className="ml-2 text-slate-400">Links</span>
          <b>{stats.link_count ?? '—'}</b>
          <span className="ml-2 text-slate-400">Contradictions</span>
          <b className={stats.contradiction_count ? 'text-rose-400' : ''}>{stats.contradiction_count ?? '—'}</b>
        </span>
        {loading && <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />}
      </div>

      <div className="flex flex-wrap gap-4 text-xs text-slate-400">
        {Object.entries({ Actor: COLORS.actor, Wallet: COLORS.btc, PGP: COLORS.pgp, 'Clearnet IP': COLORS.ip, Onion: COLORS.onion, Handle: COLORS.handle }).map(
          ([label, color]) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
              {label}
            </span>
          ),
        )}
      </div>

      {error && <div className="rounded-lg border border-rose-900 bg-rose-950/60 p-3 text-sm text-rose-300">{error}</div>}

      <div ref={containerRef} className="overflow-hidden rounded-lg border border-slate-800 bg-slate-950">
        <ForceGraph2D
          graphData={graphData}
          width={dimensions.width}
          height={dimensions.height}
          backgroundColor="#020617"
          nodeColor={nodeColor}
          nodeLabel={nodeLabel}
          nodeVal={(n) => n.val}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const label = nodeLabel(node)
            const fontSize = 11 / globalScale
            ctx.font = `${node.type === 'actor' ? 'bold ' : ''}${fontSize}px Sans-Serif`
            ctx.fillStyle = node.type === 'actor' ? '#e2e8f0' : '#94a3b8'
            ctx.textAlign = 'center'
            ctx.textBaseline = 'top'
            ctx.fillText(label, node.x, node.y + 6)
          }}
          linkColor={(l) => (l.contradiction ? '#f43f5e' : '#334155')}
          linkWidth={(l) => (l.contradiction ? 1.6 : 0.7)}
          linkDirectionalParticles={(l) => (l.contradiction ? 3 : 0)}
          linkDirectionalParticleWidth={1.6}
          cooldownTicks={120}
        />
      </div>
    </div>
  )
}
