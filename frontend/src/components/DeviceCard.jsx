import { deviceIcon, riskBand, severityCounts, prettyType } from '../deviceMeta'

export default function DeviceCard({ device, onOpen }) {
  const band = riskBand(device.risk_score)
  const counts = severityCounts(device.findings)
  const ports = (device.open_ports || []).length
  const vulnTotal = counts.critical + counts.high + counts.medium + counts.low

  return (
    <button className={`dcard band-${band}`} onClick={() => onOpen(device)}>
      <div className="dcard-top">
        <div className="dcard-icon">{deviceIcon(device.device_type)}</div>
        <div className={`score ${band}`}>{device.risk_score ?? '—'}</div>
      </div>

      <div className="dcard-name mono">{device.ip_address}</div>
      <div className="dcard-sub">
        {device.vendor || 'Unknown vendor'} · {prettyType(device.device_type)}
      </div>
      {device.internet_facing ? <span className="tag" style={{ marginLeft: 0 }}>internet-facing</span> : null}

      <div className="dcard-meta">
        <span className="muted">{ports} port{ports === 1 ? '' : 's'}</span>
        {vulnTotal > 0 ? (
          <span className="dcard-vulns">
            {counts.critical > 0 && <span className="dot-badge critical">{counts.critical}</span>}
            {counts.high > 0 && <span className="dot-badge high">{counts.high}</span>}
            {counts.medium > 0 && <span className="dot-badge medium">{counts.medium}</span>}
            {counts.low > 0 && <span className="dot-badge low">{counts.low}</span>}
          </span>
        ) : (
          <span className="pill low">clean</span>
        )}
      </div>
      <div className="dcard-cta">View details →</div>
    </button>
  )
}
