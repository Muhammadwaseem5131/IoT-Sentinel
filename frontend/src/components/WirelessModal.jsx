import { useState, useEffect } from 'react'
import * as api from '../api'
import { renderMarkdown } from '../safeMarkdown'

// Built-in, offline explanations per finding type (no AI needed).
const WIFI_INFO = {
  weak_encryption: {
    icon: '🔓', severity: 'high', title: 'Weak or no WiFi encryption',
    what: 'This network uses WEP or is open. WEP can be cracked in minutes; open networks send everything in the clear.',
    risk: 'Anyone nearby can read your traffic (passwords, messages) or join the network and attack your devices.',
    fix: 'In the router admin page, set security to WPA2 or WPA3 with a strong passphrase, and disable WEP/open.',
  },
  wps_enabled: {
    icon: '🔑', severity: 'high', title: 'WPS enabled (PIN brute-force risk)',
    what: 'WiFi Protected Setup (WPS) is on. Its 8-digit PIN can be brute-forced (Reaver / Pixie-Dust).',
    risk: 'An attacker can recover your full WiFi password within hours, even on a WPA2 network.',
    fix: 'Open the router admin page and disable WPS. Reconnect devices manually with the WiFi password.',
  },
  deauth_detected: {
    icon: '⚠️', severity: 'high', title: 'Deauthentication attack detected',
    what: 'Deauth frames were seen forcing devices off this network.',
    risk: 'Someone may be jamming your WiFi or knocking devices off to capture the handshake or run an evil-twin attack.',
    fix: 'Switch to WPA3 (protected management frames) or enable 802.11w if available, and investigate the source of the frames.',
  },
  rogue_ap: {
    icon: '👥', severity: 'high', title: 'Possible evil-twin / rogue access point',
    what: 'The same network name is being broadcast from more than one device (BSSID) at once.',
    risk: 'This is a common evil-twin attack: an attacker clones your network name to trick devices into '
      + 'connecting to them instead, capturing traffic or credentials. It can also be a legitimate mesh/extender.',
    fix: 'Check every access point broadcasting this name is one you or your ISP set up. If not, it may be an attacker nearby.',
  },
  default_ssid: {
    icon: '🏭', severity: 'medium', title: 'Factory-default network name',
    what: "This network's name matches a factory-default pattern (e.g. \"NETGEAR54\", \"TP-LINK_A1B2\").",
    risk: 'A default name usually means the admin password and firmware were never changed either, '
      + 'the whole device is likely running on defaults an attacker already knows.',
    fix: "Log in to the router's admin page, set a unique network name and a strong admin password, and update the firmware.",
  },
  info: {
    icon: '🔐', severity: 'low', title: 'Network looks OK',
    what: 'This network appears to use standard, modern encryption (e.g. WPA2/WPA3).',
    risk: 'No specific weakness was found here.',
    fix: 'Keep router firmware updated and use a long, unique WiFi passphrase.',
  },
}

export default function WirelessModal({ finding, scanId, onClose }) {
  const [ai, setAi] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  if (!finding) return null
  const info = WIFI_INFO[finding.finding_type] || WIFI_INFO.info

  const explain = async () => {
    setAiLoading(true); setAiError(''); setAi(null)
    try {
      const { explanation } = await api.explainWireless(scanId, finding.id)
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
          <div className={`dcard-icon band-${info.severity}`} style={{ width: 60, height: 60, fontSize: 30 }}>
            {info.icon}
          </div>
          <div>
            <h2 style={{ margin: 0 }}>{finding.ssid || 'hidden network'}</h2>
            <div className="muted">🔐 {finding.encryption || 'unknown'} · <span className="mono">{finding.bssid || '—'}</span></div>
            <span className={`pill ${info.severity}`} style={{ marginTop: 4, display: 'inline-block' }}>{finding.finding_type}</span>
          </div>
        </div>

        <div className="modal-body">
          <section>
            <h4>{info.title}</h4>
            <div className="vuln-list">
              <div className={`vuln-item ${info.severity}`}>
                <div className="vuln-head"><strong>What it is</strong></div>
                <div className="vuln-desc">{info.what}</div>
              </div>
              <div className={`vuln-item ${info.severity}`}>
                <div className="vuln-head"><strong>Why it matters</strong></div>
                <div className="vuln-desc">{info.risk}</div>
              </div>
              <div className="vuln-item low">
                <div className="vuln-head"><strong>How to fix it</strong></div>
                <div className="vuln-desc">{info.fix}</div>
              </div>
            </div>
            {finding.details && <p className="faint" style={{ fontSize: 12, marginTop: 10 }}>Observed: {finding.details}</p>}
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
                Get a tailored, plain-language explanation for this network. No provider set up yet? Add a key
                in Settings first (or use local Ollama, free, no key needed).
              </p>
            )}
            {ai && <div className="report" style={{ marginTop: 12 }} dangerouslySetInnerHTML={{ __html: renderMarkdown(ai) }} />}
          </section>
        </div>
      </div>
    </div>
  )
}
