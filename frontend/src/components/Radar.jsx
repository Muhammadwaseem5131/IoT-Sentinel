import { BAND_COLOR } from '../deviceMeta'

const SIZE = 280
const CENTER = SIZE / 2
const MAX_R = CENTER - 26

// Stable, deterministic placement per network (same BSSID always lands in the
// same spot) so blips don't jump around on re-render. Not a real position,
// just a consistent scatter for the radar visual.
function hashAngleRadius(seed) {
  let h = 0
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0
  const angle = (h % 360) * (Math.PI / 180)
  const radius = 0.28 + ((h >> 8) % 100) / 100 * 0.66
  return { angle, radius }
}

// Wireless findings carry a finding_type, not a numeric risk score, map that
// straight to a severity band for the blip color.
function networkBand(findingType) {
  if (findingType === 'weak_encryption') return 'critical'
  if (findingType === 'rogue_ap' || findingType === 'wps_enabled' || findingType === 'deauth_detected') return 'high'
  if (findingType === 'default_ssid') return 'medium'
  return 'low'
}

export default function Radar({ networks, monitorIface, scanning, onScan }) {
  const rings = [0.33, 0.66, 1]
  const list = networks || []
  const hasScanned = networks != null
  const atRisk = list.filter((n) => n.finding_type !== 'info').length
  const band = !hasScanned ? 'none' : atRisk > 0 ? 'high' : 'low'

  return (
    <div className="card radar-card">
      <div className="radar-wrap">
        <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`} className="radar-svg">
          <defs>
            <linearGradient id="radar-gradient" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity="0" />
              <stop offset="100%" stopColor="var(--accent-2)" stopOpacity="0.9" />
            </linearGradient>
          </defs>
          {rings.map((r) => (
            <circle key={r} cx={CENTER} cy={CENTER} r={MAX_R * r} className="radar-ring" />
          ))}
          <line x1={CENTER} y1={26} x2={CENTER} y2={SIZE - 26} className="radar-crosshair" />
          <line x1={26} y1={CENTER} x2={SIZE - 26} y2={CENTER} className="radar-crosshair" />

          <g className="radar-sweep-group">
            <path
              d={`M ${CENTER} ${CENTER} L ${CENTER} ${CENTER - MAX_R} A ${MAX_R} ${MAX_R} 0 0 1 ${CENTER + MAX_R * Math.sin(0.6)} ${CENTER - MAX_R * Math.cos(0.6)} Z`}
              className="radar-sweep"
            />
          </g>

          {list.map((n) => {
            const { angle, radius } = hashAngleRadius(n.bssid || n.ssid || 'hidden')
            const r = MAX_R * radius
            const x = CENTER + Math.cos(angle) * r
            const y = CENTER + Math.sin(angle) * r
            const nband = networkBand(n.finding_type)
            return (
              <g key={n.bssid} className="radar-blip-group" style={{ transformOrigin: `${x}px ${y}px` }}>
                <circle cx={x} cy={y} r="9" fill={BAND_COLOR[nband]} opacity="0.22" className="radar-blip-pulse" />
                <circle cx={x} cy={y} r="4" fill={BAND_COLOR[nband]} className="radar-blip" />
              </g>
            )
          })}

          <circle cx={CENTER} cy={CENTER} r="3" className="radar-center" />
        </svg>
      </div>

      <div className="radar-readout">
        <div className={`radar-score band-${band}`}>{hasScanned ? atRisk : '—'}</div>
        <div className="radar-label">{hasScanned ? 'networks at risk' : 'no scan yet'}</div>
        <div className="radar-count">{list.length} network{list.length === 1 ? '' : 's'} on radar</div>
      </div>

      <button className="radar-scan-btn" onClick={onScan} disabled={scanning || !monitorIface}>
        {scanning ? <span className="spinner" /> : '📡 Scan Networks (15s)'}
      </button>

      {!monitorIface && (
        <p className="radar-hint">No adapter is in monitor mode yet. Enable one above, this unlocks automatically.</p>
      )}
      {monitorIface && !hasScanned && !scanning && (
        <p className="radar-hint">Listens passively on <span className="mono">{monitorIface}</span> for nearby WiFi networks. No packets are sent to anyone during this step.</p>
      )}
    </div>
  )
}
