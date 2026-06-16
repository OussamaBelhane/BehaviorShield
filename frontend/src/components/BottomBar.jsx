import { useContext } from 'react'
import { ThreatContext } from '../App.jsx'

function Dot({ color }) {
  return (
    <span style={{
      display: 'inline-block',
      width: 5, height: 5, borderRadius: '50%',
      background: color,
      boxShadow: `0 0 5px ${color}`,
      flexShrink: 0,
      animation: 'pulseDot 2.5s ease-in-out infinite',
    }} />
  )
}

function Divider() {
  return <span style={{ width: 1, height: 12, background: 'rgba(255,255,255,0.06)', flexShrink: 0 }} />
}

function StatusItem({ dotColor, label, value, dimValue }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {dotColor && <Dot color={dotColor} />}
      <span style={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 9, color: 'var(--text-muted)',
        letterSpacing: '0.1em', textTransform: 'uppercase',
      }}>
        {label}
      </span>
      <span style={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 10, fontWeight: 700,
        color: dimValue ? 'var(--text-muted)' : dotColor || 'var(--text-sec)',
        letterSpacing: '0.05em',
      }}>
        {value}
      </span>
    </div>
  )
}

export default function BottomBar({ status }) {
  const { threatsBlocked } = useContext(ThreatContext)

  return (
    <footer style={{
      position: 'sticky',
      bottom: 0, zIndex: 40,
      background: 'rgba(5,7,14,0.94)',
      backdropFilter: 'blur(14px)',
      borderTop: '1px solid rgba(0,212,255,0.07)',
      padding: '0 1.5rem',
      height: 30,
      display: 'flex',
      alignItems: 'center',
      gap: 18,
      flexShrink: 0,
    }}>
      {/* Top gradient accent */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 1,
        background: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.12), transparent)',
        pointerEvents: 'none',
      }} />

      <StatusItem dotColor="#00FF94" label="AGENT" value="v1.0.0" />
      <Divider />
      <StatusItem dotColor="#00FF94" label="SYSMON" value="ACTIVE" />
      <Divider />
      <StatusItem dotColor="#00D4FF" label="SQLITE" value="WAL" />
      <Divider />
      <StatusItem dotColor="#00D4FF" label="WINVERIFYTRUST" value="ACTIVE" />
      <Divider />
      <StatusItem label="EVENTS" value={status?.total_events ?? 0} dotColor="#8899B0" dimValue />
      <Divider />
      <StatusItem dotColor="#FF2D55" label="BLOCKED" value={threatsBlocked ?? status?.killed_processes ?? 0} />

      <div style={{
        marginLeft: 'auto',
        fontFamily: '"JetBrains Mono"', fontSize: 8,
        color: 'var(--text-muted)', letterSpacing: '0.1em',
        opacity: 0.7,
      }}>
        BEHAVIORSHIELD · PFA 2026
      </div>
    </footer>
  )
}
