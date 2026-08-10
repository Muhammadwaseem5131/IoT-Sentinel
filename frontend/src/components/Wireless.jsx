import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import * as api from '../api'
import Adapters from './Adapters'
import Radar from './Radar'

const TESTS = {
  wps: {
    label: 'Test WPS vulnerability',
    run: (iface, bssid) => api.checkWps(iface, bssid, true),
    vulnerable: (r) => r.wps_enabled,
    resultLabel: (r) => (r.wps_enabled ? 'WPS vulnerable' : 'WPS locked/off'),
    successToast: 'WPS is enabled and unlocked, vulnerable to PIN attacks',
    safeToast: 'WPS locked or not offered',
  },
  pmkid: {
    label: 'Test PMKID capture',
    run: (iface, bssid) => api.checkPmkid(iface, bssid, true),
    vulnerable: (r) => r.pmkid_found,
    resultLabel: (r) => (r.pmkid_found ? 'PMKID captured' : 'No PMKID'),
    successToast: 'PMKID captured, this network is vulnerable to offline password guessing',
    safeToast: 'No PMKID captured in this window',
  },
}

export default function Wireless() {
  const [monitorIface, setMonitorIface] = useState(null)
  const [networks, setNetworks] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [busyKey, setBusyKey] = useState(null)       // "bssid:kind" currently running
  const [confirmKey, setConfirmKey] = useState(null) // "bssid:kind" awaiting confirmation
  const [results, setResults] = useState({})         // bssid -> { wps: {...}, pmkid: {...} }

  const refreshAdapter = () => {
    api.getAdapters().then((d) => {
      const active = d.adapters?.find((a) => a.mode === 'monitor')
      setMonitorIface(active?.interface || null)
    }).catch(() => setMonitorIface(null))
  }

  useEffect(() => { refreshAdapter() }, [])

  const scan = async () => {
    if (!monitorIface) {
      toast.error('Enable monitor mode on an adapter first (below).')
      return
    }
    setScanning(true); setNetworks(null)
    try {
      const { networks } = await api.discoverNetworks(monitorIface, 15)
      setNetworks(networks)
      toast.success(`Found ${networks.length} network${networks.length === 1 ? '' : 's'}`)
    } catch (e) {
      toast.error(e.message)
    } finally {
      setScanning(false)
    }
  }

  const runTest = async (kind, bssid) => {
    const key = `${bssid}:${kind}`
    setConfirmKey(null); setBusyKey(key)
    try {
      const result = await TESTS[kind].run(monitorIface, bssid)
      setResults((prev) => ({ ...prev, [bssid]: { ...prev[bssid], [kind]: result } }))
      const t = TESTS[kind]
      toast[t.vulnerable(result) ? 'error' : 'success'](t.vulnerable(result) ? t.successToast : t.safeToast)
    } catch (e) {
      toast.error(e.message)
    } finally {
      setBusyKey(null)
    }
  }

  return (
    <>
      <div className="card">
        <h3>📡 Wireless Audit</h3>
        <p className="status">
          A dedicated space for the wireless module: enable monitor mode on an adapter, scan the air for
          nearby networks, and run active tests against a specific network you own or are authorized to test.
        </p>
      </div>

      <Adapters onMonitorChange={refreshAdapter} />

      <Radar networks={networks} monitorIface={monitorIface} scanning={scanning} onScan={scan} />

      <div className="card">
        {networks && (
          networks.length === 0 ? (
            <p className="status" style={{ marginTop: 12 }}>No networks heard in range.</p>
          ) : (
            <div className="wifi-grid" style={{ marginTop: 14 }}>
              {networks.map((n) => (
                <div key={n.bssid} className={`wifi-card ${n.finding_type === 'info' ? 'ok' : 'warn'}`} style={{ cursor: 'default' }}>
                  <div className="wifi-card-head">
                    <span className="wifi-ssid">{n.ssid || 'hidden'}</span>
                    <span className={`pill ${n.finding_type === 'info' ? 'info' : 'high'}`}>{n.finding_type}</span>
                  </div>
                  <div className="mono faint" style={{ fontSize: 11 }}>{n.bssid}</div>
                  <div className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>🔐 {n.encryption || 'unknown'}</div>
                  <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{n.details}</div>

                  <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}>
                    {Object.entries(TESTS).map(([kind, t]) => {
                      const key = `${n.bssid}:${kind}`
                      const result = results[n.bssid]?.[kind]
                      if (result) {
                        return (
                          <span key={kind} className={`pill ${t.vulnerable(result) ? 'critical' : 'low'}`}>
                            {t.resultLabel(result)}
                          </span>
                        )
                      }
                      if (confirmKey === key) {
                        return (
                          <div key={kind} className="row" style={{ gap: 8 }}>
                            <button className="ghost" onClick={() => setConfirmKey(null)}>Cancel</button>
                            <button className="primary" onClick={() => runTest(kind, n.bssid)}>
                              Confirm, send test packets
                            </button>
                          </div>
                        )
                      }
                      return (
                        <button key={kind} className="subtle" onClick={() => setConfirmKey(key)} disabled={busyKey === key}>
                          {busyKey === key ? <span className="spinner" /> : t.label}
                        </button>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </div>

      <div className="card">
        <h4 style={{ marginTop: 0 }}>What the active tests do</h4>
        <p className="faint" style={{ fontSize: 12.5 }}>
          <strong>Test WPS vulnerability</strong> sends WPS probe frames to check whether PIN-based WPS is
          enabled and unlocked, an attacker within range could brute-force the PIN and recover the WiFi
          password in hours.
        </p>
        <p className="faint" style={{ fontSize: 12.5 }}>
          <strong>Test PMKID capture</strong> requests the network's PMKID directly, the least-intrusive way
          to check whether its WPA2 key is vulnerable to offline password guessing. It never deauthenticates
          anyone or needs a connected client.
        </p>
        <p className="faint" style={{ fontSize: 12.5, marginBottom: 0 }}>
          Both transmit to the target network, unlike the passive scan above, so each only runs after you
          confirm. Only test networks you own or are explicitly authorized to test.
        </p>
      </div>
    </>
  )
}
