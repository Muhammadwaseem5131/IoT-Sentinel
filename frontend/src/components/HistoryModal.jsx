import { useEffect } from 'react'

export default function HistoryModal({ scans, onView, onClose }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        <div className="modal-head">
          <div className="dcard-icon" style={{ width: 52, height: 52, fontSize: 26 }}>🕘</div>
          <div>
            <h2 style={{ margin: 0 }}>Scan History</h2>
            <div className="muted">{scans.length} scan{scans.length === 1 ? '' : 's'}, open one to view its results</div>
          </div>
        </div>
        <div className="modal-body">
          {scans.length === 0 ? (
            <div className="empty"><div className="big">🔍</div>No scans yet.</div>
          ) : (
            <table>
              <thead>
                <tr><th>ID</th><th>Target</th><th>Type</th><th>Started</th><th>Status</th><th></th></tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">#{s.id}</td>
                    <td>{s.subnet}</td>
                    <td><span className="muted">{s.scan_type}</span></td>
                    <td className="muted mono" style={{ fontSize: 11.5 }}>{s.started_at}</td>
                    <td>
                      <span className={`pill ${s.status === 'completed' ? 'low' : s.status === 'failed' ? 'critical' : 'info'}`}>
                        {s.status}
                      </span>
                    </td>
                    <td><button className="ghost" onClick={() => onView(s.id)}>View</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
