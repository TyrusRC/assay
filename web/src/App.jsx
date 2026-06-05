import React, { useEffect, useState, useCallback } from 'react'
import { listScans, createScan, getReport, reportURL } from './api.js'

const PROFILES = ['', 'quick', 'normal', 'thorough', 'passive']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const FORMATS = ['json', 'html', 'csv', 'md', 'sarif', 'junit', 'gitlab']

export default function App() {
  const [scans, setScans] = useState([])
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      setScans(await listScans())
    } catch (e) {
      setError(String(e.message || e))
    }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 2000)
    return () => clearInterval(t)
  }, [refresh])

  return (
    <div className="app">
      <header>
        <h1>assay</h1>
        <span className="tagline">context-aware web vulnerability scanner</span>
      </header>
      <main>
        <section className="left">
          <NewScan onError={setError} onCreated={refresh} />
          {error && <div className="error" onClick={() => setError('')}>{error}</div>}
          <ScanList scans={scans} selectedId={selected?.id} onSelect={setSelected} />
        </section>
        <section className="right">
          {selected ? <ScanDetail scan={selected} /> : <Empty />}
        </section>
      </main>
    </div>
  )
}

function NewScan({ onCreated, onError }) {
  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState('normal')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (!target.trim()) return
    setBusy(true)
    try {
      await createScan({ target: target.trim(), profile: profile || undefined })
      setTarget('')
      onCreated()
    } catch (err) {
      onError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="newscan card" onSubmit={submit}>
      <h2>New scan</h2>
      <input
        type="text"
        placeholder="https://example.com"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
      />
      <label>
        Profile
        <select value={profile} onChange={(e) => setProfile(e.target.value)}>
          {PROFILES.map((p) => (
            <option key={p || 'default'} value={p}>{p || 'default'}</option>
          ))}
        </select>
      </label>
      <button type="submit" disabled={busy}>{busy ? 'Starting…' : 'Start scan'}</button>
    </form>
  )
}

function ScanList({ scans, selectedId, onSelect }) {
  if (!scans.length) return <p className="muted">No scans yet.</p>
  return (
    <ul className="scanlist">
      {[...scans].reverse().map((s) => (
        <li
          key={s.id}
          className={s.id === selectedId ? 'active' : ''}
          onClick={() => onSelect(s)}
        >
          <div className="row">
            <span className="target">{s.target}</span>
            <StatusBadge status={s.status} />
          </div>
          <div className="row small muted">
            <span>{s.profile || 'default'}</span>
            {s.summary && <SeverityChips summary={s.summary} />}
          </div>
        </li>
      ))}
    </ul>
  )
}

function ScanDetail({ scan }) {
  const [report, setReport] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    setReport(null)
    setErr('')
    if (scan.status !== 'completed') return
    getReport(scan.id).then(setReport).catch((e) => setErr(String(e.message || e)))
  }, [scan.id, scan.status])

  const findings = report?.scan_result?.findings || []

  return (
    <div className="detail">
      <div className="detail-head">
        <div>
          <h2>{scan.target}</h2>
          <div className="muted small">{scan.id}</div>
        </div>
        <StatusBadge status={scan.status} />
      </div>

      {scan.status === 'failed' && <div className="error">{scan.error}</div>}
      {scan.status !== 'completed' && scan.status !== 'failed' && (
        <p className="muted">Scan {scan.status}…</p>
      )}

      {scan.status === 'completed' && (
        <>
          {scan.summary && <SummaryBar summary={scan.summary} />}
          <div className="downloads">
            Download:
            {FORMATS.map((f) => (
              <a key={f} href={reportURL(scan.id, f)} target="_blank" rel="noreferrer">{f}</a>
            ))}
          </div>
          {err && <div className="error">{err}</div>}
          <FindingsTable findings={findings} />
        </>
      )}
    </div>
  )
}

function FindingsTable({ findings }) {
  if (!findings.length) return <p className="muted">No findings.</p>
  const sorted = [...findings].sort(
    (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity),
  )
  return (
    <table className="findings">
      <thead>
        <tr><th>Severity</th><th>Type</th><th>CVSS</th><th>URL</th><th>Param</th></tr>
      </thead>
      <tbody>
        {sorted.map((f) => (
          <tr key={f.id}>
            <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
            <td>{f.type}</td>
            <td>{f.cvss ? f.cvss.toFixed(1) : '—'}</td>
            <td className="url">{f.url}</td>
            <td>{f.parameter || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function SummaryBar({ summary }) {
  const counts = {
    critical: summary.Critical, high: summary.High, medium: summary.Medium,
    low: summary.Low, info: summary.Info,
  }
  return (
    <div className="summary">
      {SEVERITIES.map((s) => (
        <div key={s} className={`stat ${s}`}>
          <div className="n">{counts[s] || 0}</div>
          <div className="lbl">{s}</div>
        </div>
      ))}
    </div>
  )
}

function SeverityChips({ summary }) {
  const items = [
    ['critical', summary.Critical], ['high', summary.High], ['medium', summary.Medium],
  ].filter(([, n]) => n > 0)
  if (!items.length) return <span className="muted small">clean</span>
  return (
    <span>
      {items.map(([s, n]) => (
        <span key={s} className={`chip ${s}`}>{n}</span>
      ))}
    </span>
  )
}

function StatusBadge({ status }) {
  return <span className={`status ${status}`}>{status}</span>
}

function Empty() {
  return (
    <div className="empty muted">
      <p>Select a scan to view its findings, or start a new one.</p>
    </div>
  )
}
