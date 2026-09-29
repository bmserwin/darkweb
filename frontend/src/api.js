const BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? body)
    } catch {
      /* non-JSON error body - keep the status line */
    }
    throw new Error(detail)
  }
  return res.json()
}

export const api = {
  health: () => request('/health'),
  ingest: (payload) =>
    request('/ingest', { method: 'POST', body: JSON.stringify(payload) }),
  observations: (limit = 25) => request(`/ingest/observations?limit=${limit}`),
  graph: (cutoffTime) =>
    request(`/graph${cutoffTime ? `?cutoff_time=${encodeURIComponent(cutoffTime)}` : ''}`),
  graphSummary: (cutoffTime) =>
    request(`/graph/summary${cutoffTime ? `?cutoff_time=${encodeURIComponent(cutoffTime)}` : ''}`),
  actors: () => request('/actors'),
  adjudicationQueue: () => request('/adjudication/queue'),
  adjudicationAction: (candidateId, action, analystNotes) =>
    request('/adjudication/action', {
      method: 'POST',
      body: JSON.stringify({ candidate_id: candidateId, action, analyst_notes: analystNotes }),
    }),
  infraScan: (target) =>
    request('/infra/scan', { method: 'POST', body: JSON.stringify({ target, fetch_pages: true }) }),
  auditVerify: () => request('/audit/verify'),
  auditLedger: (limit = 60) => request(`/audit/ledger?limit=${limit}`),
  auditTamper: (blockIndex) =>
    request('/audit/tamper', { method: 'POST', body: JSON.stringify({ block_index: blockIndex }) }),
  auditRestore: (blockIndex) =>
    request(`/audit/restore?block_index=${blockIndex}`, { method: 'POST' }),
  dossierUrl: (handle) => `${BASE}/reports/pdf/${encodeURIComponent(handle)}`,
  stixUrl: (handle) => `${BASE}/reports/stix/${encodeURIComponent(handle)}`,
}

export default api
