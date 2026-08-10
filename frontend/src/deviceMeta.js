// Device-type -> emoji icon. Reliable, offline, no external images.
const ICONS = {
  router: '📡', gateway: '📡',
  camera: '📷',
  printer: '🖨️',
  speaker: '🔊',
  tv: '📺',
  phone: '📱',
  raspberry_pi: '🍓',
  windows_host: '💻', pc: '💻', laptop: '💻',
  nas: '🗄️',
  smart_lock: '🔒',
  hub: '🧩', iot_hub: '🧩',
  switch: '🔀',
  plc: '🏭',
  thermostat: '🌡️',
}

export function deviceIcon(type) {
  return ICONS[type] || '📟'
}

export function riskBand(score) {
  if (score == null) return 'none'
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

export const BAND_COLOR = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', none: '#5c6780',
}

// Count real (non-info) findings by severity.
export function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of findings || []) {
    if (f.finding_type === 'info') continue
    if (counts[f.severity] != null) counts[f.severity]++
  }
  return counts
}

export function prettyType(type) {
  if (!type) return 'Unknown device'
  return type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}
