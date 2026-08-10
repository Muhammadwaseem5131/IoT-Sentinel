import { useState, useEffect } from 'react'
import * as api from '../api'

export default function Adapters({ onMonitorChange }) {
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState('')
  const [msg, setMsg] = useState('')
  const [error, setError] = useState('')

  const load = () => api.getAdapters().then(setData).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const toggle = async (iface, enable) => {
    setBusy(iface); setError(''); setMsg('')
    try {
      const r = await api.setMonitor(iface, enable)
      setMsg(r.monitor_interface
        ? `Monitor mode enabled on ${r.monitor_interface}.`
        : (r.message || r.status))
      load()
      onMonitorChange?.()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="card">
      <div className="section-title">
        <h3>📶 Wireless Adapters</h3>
        <button className="ghost" onClick={load}>Refresh</button>
      </div>
      <p className="status">
        Detects WiFi adapters and whether they can run the wireless module (monitor mode).
        Driver installation can't be automated: it needs admin rights and is OS-specific, so any
        missing step is shown as a command to run.
      </p>

      {!data && <p className="status">Detecting adapters…</p>}

      {data && (
        <>
          {!data.os_supports_monitor && (
            <div className="notice" style={{ marginBottom: 14 }}>
              Monitor mode isn't available on <strong>{data.platform}</strong>. The adapters below work as
              normal WiFi; to run the wireless module, use a Linux machine with a compatible adapter.
            </div>
          )}

          {data.adapters.length === 0 ? (
            <p className="status">No wireless adapters detected.</p>
          ) : (
            <div className="adapter-list">
              {data.adapters.map((a) => (
                <div key={a.interface} className="adapter">
                  <div className="adapter-info">
                    <div className="mono adapter-name">{a.interface}</div>
                    <div className="faint" style={{ fontSize: 12 }}>
                      driver: {a.driver}{a.mode ? ` · mode: ${a.mode}` : ''}
                    </div>
                  </div>
                  <div className="adapter-actions">
                    {a.monitor_capable
                      ? <span className="pill low">monitor-capable</span>
                      : <span className="pill" style={{ background: 'rgba(139,150,173,0.16)', color: 'var(--muted)' }}>no monitor mode</span>}
                    {data.os_supports_monitor && a.monitor_capable && (
                      a.mode === 'monitor'
                        ? <button className="ghost" onClick={() => toggle(a.interface, false)} disabled={busy === a.interface}>
                            {busy === a.interface ? <span className="spinner" /> : 'Disable'}
                          </button>
                        : <button className="primary" onClick={() => toggle(a.interface, true)} disabled={busy === a.interface}>
                            {busy === a.interface ? <span className="spinner" /> : 'Enable monitor'}
                          </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {data.tools && Object.keys(data.tools).length > 0 && (
            <div className="row" style={{ gap: 10, marginTop: 12, fontSize: 12.5 }}>
              {Object.entries(data.tools).map(([name, ok]) => (
                <span key={name} className={`pill ${ok ? 'low' : 'critical'}`}>{name} {ok ? '✓' : '✗'}</span>
              ))}
            </div>
          )}

          {data.hint && (
            <div className="notice" style={{ marginTop: 12 }}>
              💡 {data.hint}
            </div>
          )}

          {msg && <p className="status" style={{ color: 'var(--low)' }}>{msg}</p>}
          {error && <div className="error" style={{ marginTop: 10 }}>{error}</div>}
          <p className="faint" style={{ fontSize: 11.5, marginTop: 10 }}>
            Enabling monitor mode runs <span className="mono">airmon-ng</span> and needs root; it will
            temporarily disconnect this adapter from normal WiFi.
          </p>
        </>
      )}
    </div>
  )
}
