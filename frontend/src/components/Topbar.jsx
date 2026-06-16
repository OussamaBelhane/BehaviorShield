import { useEffect, useState, useContext } from 'react'
import { ThreatContext } from '../App.jsx'
import { Shield } from 'lucide-react'

function ClockChip() {
  const [time, setTime] = useState('')
  useEffect(() => {
    const tick = () => {
      const now = new Date()
      setTime(now.toLocaleTimeString('en-US', { hour12: false }))
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 7,
      padding: '4px 12px',
      background: 'rgba(0,212,255,0.06)',
      border: '1px solid rgba(0,212,255,0.12)',
      borderRadius: 6,
      fontFamily: '"JetBrains Mono", monospace',
      fontSize: 12, letterSpacing: '0.12em',
      color: 'var(--text-sec)',
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%',
        background: '#00D4FF',
        display: 'inline-block',
        animation: 'blink 1.2s step-start infinite',
        boxShadow: '0 0 6px #00D4FF',
      }} />
      {time}
    </div>
  )
}

function StatusPill({ color, glow, label }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '4px 10px',
      background: `rgba(${glow},0.06)`,
      border: `1px solid rgba(${glow},0.14)`,
      borderRadius: 6,
      fontFamily: '"JetBrains Mono", monospace',
      fontSize: 10, letterSpacing: '0.1em', fontWeight: 600,
      color,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%',
        background: color,
        boxShadow: `0 0 7px ${color}`,
        animation: 'pulseDot 2s ease-in-out infinite',
        flexShrink: 0,
      }} />
      {label}
    </div>
  )
}

export default function Topbar() {
  const { disconnected } = useContext(ThreatContext)

  return (
    <header style={{
      position: 'sticky',
      top: 0, zIndex: 40,
      background: 'rgba(5,7,14,0.92)',
      backdropFilter: 'blur(20px)',
      borderBottom: '1px solid rgba(0,212,255,0.08)',
      padding: '0 1.5rem',
      height: 54,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexShrink: 0,
    }}>
      {/* Bottom gradient accent line */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0, height: 1,
        background: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.2), rgba(0,255,148,0.15), transparent)',
        pointerEvents: 'none',
      }} />

      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* Icon */}
        <div style={{
          padding: '5px',
          background: 'rgba(0,212,255,0.08)',
          border: '1px solid rgba(0,212,255,0.15)',
          borderRadius: 8,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          filter: 'drop-shadow(0 0 8px rgba(0,212,255,0.4))',
        }}>
          <Shield size={18} color="#00D4FF" strokeWidth={1.5} />
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 0 }}>
            <span style={{
              fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 20,
              color: '#E8EDF5', letterSpacing: '0.1em',
            }}>BEHAVIOR</span>
            <span style={{
              fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 20,
              color: '#00D4FF', letterSpacing: '0.1em',
              textShadow: '0 0 18px rgba(0,212,255,0.55)',
            }}>SHIELD</span>
          </div>
          <div style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 9, color: 'var(--text-muted)',
            letterSpacing: '0.18em', marginTop: -2,
          }}>
            ENDPOINT DETECTION &amp; RESPONSE
          </div>
        </div>

        {/* Version chip */}
        <div style={{
          marginLeft: 4,
          padding: '2px 8px',
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 4,
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 9, color: 'var(--text-muted)',
          letterSpacing: '0.08em',
        }}>
          v1.0.0
        </div>
      </div>

      {/* Right status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {disconnected ? (
          <StatusPill color="#FF2D55" glow="255,45,85" label="DISCONNECTED" />
        ) : (
          <>
            <StatusPill color="#00FF94" glow="0,255,148" label="SYSMON ACTIVE" />
            <StatusPill color="#00FF94" glow="0,255,148" label="AGENT RUNNING" />
          </>
        )}
        <ClockChip />
      </div>
    </header>
  )
}
