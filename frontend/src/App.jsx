import { useState, useEffect, useRef } from 'react'
import { Toaster, toast } from 'sonner'
import * as api from './api'
import { renderMarkdown } from './safeMarkdown'
import ScanForm from './components/ScanForm'
import SummaryCards from './components/SummaryCards'
import RiskChart from './components/RiskChart'
import ScanDiff from './components/ScanDiff'
import DeviceCard from './components/DeviceCard'
import DeviceModal from './components/DeviceModal'
import WirelessModal from './components/WirelessModal'
import HistoryModal from './components/HistoryModal'
import NetworkMap from './components/NetworkMap'
import Wireless from './components/Wireless'
import Settings from './components/Settings'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export default function App() {
  const [tab, setTab] = useState('dashboard')
  const [scans, setScans] = useState([])
  const [selected, setSelected] = useState(null)
  const [report, setReport] = useState(null)
  const [diff, setDiff] = useState(null)
  const [modalDevice, setModalDevice] = useState(null)
  const [modalWireless, setModalWireless] = useState(null)
  const [showHistory, setShowHistory] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(null)
  const [wifi, setWifi] = useState(null)
  const [busy, setBusy] = useState(false)
  const [secondScan, setSecondScan] = useState(null)
  const [theme, setTheme] = useState(() => localStorage.getItem('iot-theme') || '')
  const polling = useRef(false)

  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme
    else delete document.documentElement.dataset.theme
    if (theme) localStorage.setItem('iot-theme', theme)
    else localStorage.removeItem('iot-theme')
  }, [theme])

  const toggleTheme = () => {
    const isDark = theme ? theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches
    setTheme(isDark ? 'light' : 'dark')
  }

  const refresh = async () => {
    try { setScans(await api.listScans()) } catch (e) { toast.error(e.message) }
  }

  useEffect(() => {
    refresh()
    api.wirelessStatus().then(setWifi).catch(() => setWifi({ supported: false }))
    return () => { polling.current = false }
  }, [])

  const loadScan = async (id) => {
    setReport(null); setDiff(null)
    try {
      const scan = await api.getScan(id)
      setSelected(scan)
      api.getDiff(id).then(setDiff).catch(() => setDiff(null))
      return scan
    } catch (e) { toast.error(e.message) }
  }

  const pollScan = async (id) => {
    polling.current = true
    while (polling.current) {
      let scan
      try { scan = await api.getScan(id) } catch (e) { toast.error(e.message); break }
      setSelected(scan)
      setProgress({ pct: scan.progress ?? 0, stage: scan.stage || 'Scanning…' })
      if (scan.status !== 'running') {
        if (scan.status === 'failed') toast.error(scan.error || 'Scan failed')
        else toast.success(`Scan complete: ${scan.devices?.length ?? 0} device(s) found`)
        break
      }
      await sleep(1500)
    }
    polling.current = false
    setScanning(false); setProgress(null); refresh()
    api.getDiff(id).then(setDiff).catch(() => setDiff(null))
  }

  const handleScan = async (subnet, testCreds) => {
    if (scanning) return
    setScanning(true); setReport(null); setProgress({ pct: 0, stage: 'Starting…' })
    try {
      const res = await api.startScan(subnet, testCreds)
      await refresh()
      if (res.status === 'completed') {
        const scan = await loadScan(res.scan_id); setScanning(false); setProgress(null)
        toast.success(`Scan complete: ${scan?.devices?.length ?? 0} device(s) found`)
      } else pollScan(res.scan_id)
    } catch (e) { toast.error(e.message); setScanning(false); setProgress(null) }
  }

  useEffect(() => {
    if (!selected) { setSecondScan(null); return }
    const other = scans.find((s) => s.subnet !== selected.subnet && s.status === 'completed')
    if (!other) { setSecondScan(null); return }
    api.getScan(other.id).then(setSecondScan).catch(() => setSecondScan(null))
  }, [selected, scans])

  const handleReport = async () => {
    if (!selected) return
    setBusy(true)
    try { setReport((await api.getReport(selected.id)).report); toast.success('Report generated') }
    catch (e) { toast.error(e.message) }
    finally { setBusy(false) }
  }

  const devices = selected?.devices || []
  const wirelessFindings = selected?.wireless_findings || []

  const NAV = [
    { id: 'dashboard', label: 'Dashboard', icon: '🖥️' },
    { id: 'wireless', label: 'Wireless', icon: '📡' },
    { id: 'reports', label: 'Reports', icon: '📄' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
  ]

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">IoT<span>-Sentinel</span></div>
          <div className="tagline">AI-assisted vulnerability scanner</div>
        </div>

        <nav>
          {NAV.map((n) => (
            <button key={n.id} className={tab === n.id ? 'active' : ''} onClick={() => setTab(n.id)}>
              <span className="nav-icon">{n.icon}</span>{n.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          {wifi && (
            <span className={`wifi-pill ${wifi.supported ? 'ok' : 'off'}`}>
              <span className="dot" />
              {wifi.supported ? `Wireless ready (${wifi.interfaces?.join(', ') || 'monitor mode'})` : 'Core mode, wireless off'}
            </span>
          )}
          <button className="theme-toggle" onClick={toggleTheme} title="Toggle theme">
            {(theme || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>
      </aside>

      <Toaster theme={theme === 'light' ? 'light' : theme === 'dark' ? 'dark' : 'system'} position="bottom-right" richColors />

      <main className="main">
      {tab === 'dashboard' && (
        <>
          <ScanForm onScan={handleScan} onDemo={() => handleScan('demo', false)} disabled={scanning} />

          {progress && (
            <div className="card">
              <div className="progress-head">
                <span>{progress.stage}</span><span>{progress.pct}%</span>
              </div>
              <div className="progress"><div style={{ width: `${progress.pct}%` }} /></div>
            </div>
          )}

          {!selected && scans.length > 0 && (
            <div className="notice" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>{scans.length} past scan{scans.length === 1 ? '' : 's'} available.</span>
              <button className="subtle" onClick={() => setShowHistory(true)}>🕘 Open scan history</button>
            </div>
          )}

          {selected && (
            <>
              <SummaryCards devices={devices} />
              {devices.length > 0 && (
                <div className="overview">
                  <div className="card" style={{ margin: 0 }}>
                    <h3 style={{ marginBottom: 14 }}>Risk Overview</h3>
                    <RiskChart devices={devices} />
                  </div>
                  <div className="card" style={{ margin: 0 }}>
                    <h3 style={{ marginBottom: 14 }}>Changes Since Last Scan</h3>
                    <ScanDiff diff={diff} />
                  </div>
                </div>
              )}
              <div className="card">
                <div className="section-title">
                  <h3>Discovered Devices ({devices.length})</h3>
                  <span className="faint" style={{ fontSize: 12 }}>click a device to see details &amp; fixes</span>
                </div>
                {devices.length === 0 ? (
                  <p className="status">No devices discovered.</p>
                ) : (
                  <div className="device-grid">
                    {devices.map((d) => (
                      <DeviceCard key={d.id} device={d} onOpen={setModalDevice} />
                    ))}
                  </div>
                )}
              </div>

              {wirelessFindings.length > 0 && (
                <div className="card">
                  <h3 style={{ marginBottom: 12 }}>📶 Wireless Findings</h3>
                  <div className="wifi-grid">
                    {wirelessFindings.map((w, i) => (
                      <button
                        key={w.id ?? i}
                        className={`wifi-card ${w.finding_type === 'info' ? 'ok' : 'warn'}`}
                        onClick={() => setModalWireless(w)}
                      >
                        <div className="wifi-card-head">
                          <span className="wifi-ssid">{w.ssid || 'hidden'}</span>
                          <span className={`pill ${w.finding_type === 'info' ? 'info' : 'high'}`}>{w.finding_type}</span>
                        </div>
                        <div className="mono faint" style={{ fontSize: 11 }}>{w.bssid || '—'}</div>
                        <div className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>
                          🔐 {w.encryption || 'unknown'}
                        </div>
                        <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{w.details || ''}</div>
                        <div className="dcard-cta">View details →</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {devices.length > 0 && (
                <NetworkMap subnet={selected.subnet} devices={devices} onOpenDevice={setModalDevice} />
              )}
              {secondScan && secondScan.devices?.length > 0 && (
                <NetworkMap subnet={secondScan.subnet} devices={secondScan.devices} onOpenDevice={setModalDevice} />
              )}
            </>
          )}
        </>
      )}

      {tab === 'wireless' && <Wireless />}

      {tab === 'reports' && (
        <div className="card">
          <div className="section-title">
            <h3>AI Risk Report</h3>
            <div className="row" style={{ gap: 8 }}>
              {selected && (
                <button className="subtle" onClick={() => window.open(api.reportHtmlUrl(selected.id, !!report), '_blank')}>
                  ⬇ Printable HTML
                </button>
              )}
              <button className="primary" onClick={handleReport} disabled={busy || !selected}>
                {busy ? <span className="spinner" /> : 'Generate Report'}
              </button>
            </div>
          </div>
          {!selected && <p className="status" style={{ marginTop: 14 }}>Select a scan from the Dashboard first.</p>}
          {selected && !report && !busy && (
            <p className="notice" style={{ marginTop: 14 }}>
              Uses the AI provider set in Settings. Scan data is de-identified (MACs and full IPs stripped)
              before being sent. The printable HTML works offline without a provider.
            </p>
          )}
          {report && <div className="report" dangerouslySetInnerHTML={{ __html: renderMarkdown(report) }} />}
        </div>
      )}

      {tab === 'settings' && <Settings onOpenHistory={() => setShowHistory(true)} />}

      </main>

      {modalDevice && (
        <DeviceModal device={modalDevice} scanId={selected?.id} onClose={() => setModalDevice(null)} />
      )}

      {modalWireless && (
        <WirelessModal finding={modalWireless} scanId={selected?.id} onClose={() => setModalWireless(null)} />
      )}

      {showHistory && (
        <HistoryModal
          scans={scans}
          onClose={() => setShowHistory(false)}
          onView={(id) => { loadScan(id); setTab('dashboard'); setShowHistory(false) }}
        />
      )}
    </div>
  )
}
