const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(body.detail || `Request failed (${res.status})`)
  }
  return body
}

export const listScans = () => request('/scans')
export const getScan = (id) => request(`/scans/${id}`)
export const startScan = (subnet, testCreds) =>
  request('/scans', { method: 'POST', body: JSON.stringify({ subnet, test_creds: testCreds }) })
export const getReport = (id) => request(`/scans/${id}/report`)
export const getDiff = (id) => request(`/scans/${id}/diff`)
export const explainDevice = (scanId, deviceId) =>
  request(`/scans/${scanId}/devices/${deviceId}/explain`)
export const explainWireless = (scanId, findingId) =>
  request(`/scans/${scanId}/wireless/${findingId}/explain`)
export const reportHtmlUrl = (id, ai = false) => `${BASE}/scans/${id}/report.html${ai ? '?ai=true' : ''}`
export const wirelessStatus = () => request('/wireless/status')
export const getAdapters = () => request('/wireless/adapters')
export const setMonitor = (iface, enable) =>
  request('/wireless/monitor', { method: 'POST', body: JSON.stringify({ interface: iface, enable }) })
export const runWirelessScan = (scanId, iface, duration = 15) =>
  request(`/scans/${scanId}/wireless/scan`, { method: 'POST', body: JSON.stringify({ interface: iface, duration }) })
export const discoverNetworks = (iface, duration = 15) =>
  request('/wireless/discover', { method: 'POST', body: JSON.stringify({ interface: iface, duration }) })
export const checkWps = (iface, bssid, confirm) =>
  request('/wireless/wps-check', { method: 'POST', body: JSON.stringify({ interface: iface, bssid, confirm }) })
export const checkPmkid = (iface, bssid, confirm) =>
  request('/wireless/pmkid-check', { method: 'POST', body: JSON.stringify({ interface: iface, bssid, confirm }) })
export const getAiProvider = () => request('/settings/ai-provider')
export const setAiProvider = (provider, apiKey) =>
  request('/settings/ai-provider', { method: 'POST', body: JSON.stringify({ provider, api_key: apiKey }) })
export const deleteAiProvider = (provider) =>
  request(`/settings/ai-provider/${provider}`, { method: 'DELETE' })
export const health = () => request('/health')
