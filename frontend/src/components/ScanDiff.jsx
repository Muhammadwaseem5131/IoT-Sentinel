export default function ScanDiff({ diff }) {
  if (!diff || !diff.has_previous) {
    return <p className="faint" style={{ fontSize: 13, margin: 0 }}>
      No earlier scan of this network to compare. Run another scan later to see what changed.
    </p>
  }

  const { new_devices = [], removed_devices = [], risk_changes = [] } = diff
  if (!new_devices.length && !removed_devices.length && !risk_changes.length) {
    return <p className="faint" style={{ fontSize: 13, margin: 0 }}>No changes since the previous scan.</p>
  }

  return (
    <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 7 }}>
      {new_devices.map((ip) => (
        <div key={`n${ip}`}><span className="pill low" style={{ marginRight: 8 }}>new</span>
          <span className="mono">{ip}</span> appeared on the network</div>
      ))}
      {removed_devices.map((ip) => (
        <div key={`r${ip}`}><span className="pill info" style={{ marginRight: 8 }}>gone</span>
          <span className="mono">{ip}</span> is no longer present</div>
      ))}
      {risk_changes.map((c) => (
        <div key={`c${c.ip}`}>
          <span className={`pill ${c.delta > 0 ? 'high' : 'low'}`} style={{ marginRight: 8 }}>
            {c.delta > 0 ? `▲ +${c.delta}` : `▼ ${c.delta}`}
          </span>
          <span className="mono">{c.ip}</span> risk {c.old ?? '—'} → <strong>{c.new ?? '—'}</strong>
        </div>
      ))}
    </div>
  )
}
