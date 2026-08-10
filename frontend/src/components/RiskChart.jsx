const COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }
const ORDER = ['critical', 'high', 'medium', 'low']

function band(score) {
  if (score == null) return 'low'
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

export default function RiskChart({ devices }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const d of devices) counts[band(d.risk_score)]++
  const total = devices.length || 1
  const maxRisk = devices.reduce((m, d) => Math.max(m, d.risk_score || 0), 0)

  let cumulative = 0
  const segments = ORDER.filter((k) => counts[k] > 0).map((k) => {
    const pct = (counts[k] / total) * 100
    const seg = { k, pct, offset: -cumulative }
    cumulative += pct
    return seg
  })

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
      <svg width="132" height="132" viewBox="0 0 132 132" style={{ flexShrink: 0 }}>
        <circle cx="66" cy="66" r="52" fill="none" stroke="var(--border)" strokeWidth="15" />
        {segments.map((s) => (
          <circle
            key={s.k}
            cx="66" cy="66" r="52" fill="none"
            stroke={COLORS[s.k]} strokeWidth="15"
            pathLength="100"
            strokeDasharray={`${s.pct} ${100 - s.pct}`}
            strokeDashoffset={s.offset}
            transform="rotate(-90 66 66)"
            strokeLinecap="butt"
          />
        ))}
        <text x="66" y="62" textAnchor="middle" fontSize="30" fontWeight="800" fill="var(--text)">{maxRisk}</text>
        <text x="66" y="80" textAnchor="middle" fontSize="11" fill="var(--muted)">max risk</text>
      </svg>
      <div>
        {ORDER.map((k) => (
          <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '5px 0', fontSize: 13 }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: COLORS[k] }} />
            <span style={{ minWidth: 62, color: 'var(--muted)', textTransform: 'capitalize' }}>{k}</span>
            <strong>{counts[k]}</strong>
          </div>
        ))}
      </div>
    </div>
  )
}
