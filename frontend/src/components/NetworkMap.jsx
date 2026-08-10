import { useMemo, useState } from 'react'
import * as d3 from 'd3'
import { deviceIcon, riskBand, prettyType } from '../deviceMeta'

const ROW_H = 64
const COL_W = 190
const POPOVER_W = 200

export default function NetworkMap({ subnet, devices, onOpenDevice }) {
  const [hovered, setHovered] = useState(null) // the hovered d3 node, or null

  const { nodes, links, width, height } = useMemo(() => {
    const root = d3.hierarchy({ name: subnet, isRoot: true, children: devices.map((d) => ({ device: d })) })
    const height = Math.max(ROW_H * Math.max(devices.length, 1) + 40, 160)
    const width = COL_W * 2 + 40
    const layout = d3.tree().size([height - 40, width - 80])
    layout(root)
    return {
      nodes: root.descendants().map((n) => ({ ...n, px: n.y + 40, py: n.x + 20 })),
      links: root.links().map((l) => ({
        source: { x: l.source.y + 40, y: l.source.x + 20 },
        target: { x: l.target.y + 40, y: l.target.x + 20 },
      })),
      width, height,
    }
  }, [subnet, devices])

  // Preview position: opens on whichever side has room, so it never overflows
  // the (scrollable) container and forces a jarring auto-scroll into view.
  const preview = hovered && (() => {
    const openLeft = hovered.px + 90 + POPOVER_W > width
    return {
      device: hovered.data.device,
      x: openLeft ? hovered.px - POPOVER_W - 20 : hovered.px + 90,
      y: hovered.py,
      fromRight: openLeft,
    }
  })()

  return (
    <div className="card">
      <h3 style={{ marginBottom: 4 }}>🗺️ {subnet}</h3>
      <p className="faint" style={{ fontSize: 12, margin: '0 0 12px' }}>
        {devices.length} device{devices.length === 1 ? '' : 's'}, hover one for details, click to open
      </p>
      <div className="netmap" style={{ height }} onMouseLeave={() => setHovered(null)}>
        <svg width="100%" height={height} className="netmap-svg">
          {links.map((l, i) => (
            <path
              key={i}
              d={`M ${l.source.x} ${l.source.y} C ${(l.source.x + l.target.x) / 2} ${l.source.y}, ${(l.source.x + l.target.x) / 2} ${l.target.y}, ${l.target.x} ${l.target.y}`}
              className="netmap-link"
            />
          ))}
        </svg>

        {nodes.map((n) => {
          const isRoot = n.data.isRoot
          const device = n.data.device
          const band = isRoot ? null : riskBand(device.risk_score)
          return (
            <button
              key={isRoot ? 'root' : device.id}
              className={`netmap-node glass ${isRoot ? 'root' : `band-${band}`}`}
              style={{ left: n.px, top: n.py }}
              onMouseEnter={isRoot ? undefined : () => setHovered(n)}
              onClick={isRoot ? undefined : () => onOpenDevice(device)}
            >
              <span className="netmap-icon">{isRoot ? '🌐' : deviceIcon(device.device_type)}</span>
              <span className="netmap-text">
                <span className={`netmap-name ${isRoot ? '' : 'mono'}`}>{isRoot ? subnet : device.ip_address}</span>
                {!isRoot && <span className="netmap-sub">{device.vendor || prettyType(device.device_type)}</span>}
              </span>
              {!isRoot && <span className={`netmap-dot band-${band}`} />}
            </button>
          )
        })}

        {preview && (
          <div
            className={`netmap-popover glass ${preview.fromRight ? 'from-right' : ''}`}
            style={{ left: preview.x, top: preview.y }}
          >
            <div className="netmap-popover-head">
              <span>{deviceIcon(preview.device.device_type)}</span>
              <strong className="mono">{preview.device.ip_address}</strong>
            </div>
            <div className="faint" style={{ fontSize: 12 }}>
              {preview.device.vendor || 'Unknown'} · {prettyType(preview.device.device_type)}
            </div>
            <div className="row" style={{ marginTop: 8, gap: 8 }}>
              <span className={`score ${riskBand(preview.device.risk_score)}`}>{preview.device.risk_score ?? '—'}</span>
              <span className="faint" style={{ fontSize: 11 }}>click card to open</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
