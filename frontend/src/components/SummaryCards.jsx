function band(score) {
  if (score == null) return 'low'
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

export default function SummaryCards({ devices }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const d of devices) counts[band(d.risk_score)]++

  const tiles = [
    { key: 'total', n: devices.length, l: 'Devices' },
    { key: 'critical', n: counts.critical, l: 'Critical' },
    { key: 'high', n: counts.high, l: 'High' },
    { key: 'medium', n: counts.medium, l: 'Medium' },
    { key: 'low', n: counts.low, l: 'Low / Clean' },
  ]

  return (
    <div className="stats">
      {tiles.map((t) => (
        <div key={t.key} className={`tile ${t.key}`}>
          <span className="bar" />
          <div className="n">{t.n}</div>
          <div className="l">{t.l}</div>
        </div>
      ))}
    </div>
  )
}
