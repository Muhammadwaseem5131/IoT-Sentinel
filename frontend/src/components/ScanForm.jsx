import { useState } from 'react'

export default function ScanForm({ onScan, onDemo, disabled }) {
  const [subnet, setSubnet] = useState('')
  const [testCreds, setTestCreds] = useState(false)

  const submit = (e) => {
    e.preventDefault()
    onScan(subnet.trim(), testCreds)
  }

  return (
    <div className="card">
      <div className="section-title">
        <h3>New Scan</h3>
        <button className="subtle" type="button" onClick={onDemo} disabled={disabled}>
          ▶ Load sample data
        </button>
      </div>
      <form className="row" onSubmit={submit} style={{ marginTop: 14 }}>
        <input
          type="text"
          value={subnet}
          onChange={(e) => setSubnet(e.target.value)}
          placeholder="192.168.1.0/24"
          aria-label="Subnet"
          required
          style={{ minWidth: 200 }}
        />
        <label style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <input type="checkbox" checked={testCreds} onChange={(e) => setTestCreds(e.target.checked)} />
          Active checks <span className="faint">(default creds, anon-FTP, SNMP, MQTT; intrusive, opt-in)</span>
        </label>
        <button className="primary" type="submit" disabled={disabled}>
          {disabled ? <span className="spinner" /> : 'Start Scan'}
        </button>
      </form>
      <p className="status" style={{ marginBottom: 0, marginTop: 12 }}>
        Only scan networks you own or are authorized to test. No hardware? Use <strong>sample data</strong> to
        explore the dashboard.
      </p>
    </div>
  )
}
