// Thin client for the assay JSON API.

export async function listScans() {
  const res = await fetch('/api/scans')
  if (!res.ok) throw new Error(`list scans: ${res.status}`)
  return res.json()
}

export async function createScan(req) {
  const res = await fetch('/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `create scan: ${res.status}`)
  }
  return res.json()
}

export async function getReport(id) {
  const res = await fetch(`/api/scans/${id}/report?format=json`)
  if (!res.ok) throw new Error(`report: ${res.status}`)
  return res.json()
}

// reportURL builds a download link for a scan report in the given format.
export function reportURL(id, format) {
  return `/api/scans/${id}/report?format=${format}`
}
