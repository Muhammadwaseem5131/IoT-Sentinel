import { useState, useEffect } from 'react'
import * as api from '../api'
import { deviceIcon, riskBand, prettyType } from '../deviceMeta'
import { renderMarkdown } from '../safeMarkdown'

export default function DeviceModal({ device, scanId, onClose }) {
  const [ai, setAi] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')

  // Close on Escape.
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  if (!device) return null
  const band = riskBand(device.risk_score)
  const findings = (device.findings || []).filter((f) => f.finding_type !== 'info')
  const ports = device.open_ports || []

  const explain = async () => {
    setAiLoading(true); setAiError(''); setAi(null)
    try {
      const { explanation } = await api.explainDevice(scanId, device.id)
      setAi(explanation)
    } catch (e) {
      setAiError(e.message)
    } finally {
      setAiLoading(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>

        <div className="modal-head">
          <div className={`dcard-icon band-${band}`} style={{ width: 60, height: 60, fontSize: 30 }}>
            {deviceIcon(device.device_type)}
          </div>
          <div>
            <h2 className="mono" style={{ margin: 0 }}>{device.ip_address}</h2>
            <div className="muted">
              {device.vendor || 'Unknown vendor'} · {prettyType(device.device_type)}
              {device.hostname ? ` · ${device.hostname}` : ''}
            </div>
            {device.internet_facing ? <span className="tag" style={{ marginLeft: 0 }}>internet-facing</span> : null}
          </div>
          <div className={`score ${band}`} style={{ marginLeft: 'auto', minWidth: 54, height: 40, fontSize: 20 }}>
            {device.risk_score ?? '—'}
          </div>
        </div>

        <div className="modal-body">
          <section>
            <h4>Open ports &amp; services</h4>
            {ports.length === 0 ? (
              <p className="muted" style={{ fontSize: 13 }}>No open ports detected.</p>
            ) : (
              <div className="chip-row">
                {ports.map((p, i) => (
                  <span key={i} className="chip mono">
                    {p.port}/{p.service || 'tcp'}{p.banner ? ` · ${p.banner}` : ''}
                  </span>
                ))}
              </div>
            )}
          </section>

          <section>
            <h4>Vulnerabilities ({findings.length})</h4>
            {findings.length === 0 ? (
              <p className="pill low" style={{ display: 'inline-block' }}>No known vulnerabilities matched</p>
            ) : (
              <div className="vuln-list">
                {findings.map((f, i) => (
                  <div key={i} className={`vuln-item ${f.severity || 'low'}`}>
                    <div className="vuln-head">
                      <span className={`pill ${f.severity || 'low'}`}>{f.severity}</span>
                      {f.cve_id ? <span className="mono" style={{ color: 'var(--accent-2)' }}>{f.cve_id}</span> : null}
                      <span className="faint" style={{ fontSize: 11 }}>{f.finding_type}</span>
                    </div>
                    <div className="vuln-desc">{f.description}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section>
            <div className="section-title">
              <h4 style={{ margin: 0 }}>Explain &amp; Fix</h4>
              {!ai && (
                <button className="primary" onClick={explain} disabled={aiLoading}>
                  {aiLoading ? <span className="spinner" /> : 'Explain & Fix'}
                </button>
              )}
            </div>
            {aiError && <div className="error" style={{ marginTop: 12 }}>{aiError}</div>}
            {!ai && !aiLoading && !aiError && (
              <p className="notice" style={{ marginTop: 12 }}>
                Get a plain-language explanation of this device's risks and how to fix them. No provider set up
                yet? Add a key in Settings first (or use local Ollama, free, no key needed).
              </p>
            )}
            {ai && <div className="report" style={{ marginTop: 12 }} dangerouslySetInnerHTML={{ __html: renderMarkdown(ai) }} />}
          </section>
        </div>
      </div>
    </div>
  )
}
