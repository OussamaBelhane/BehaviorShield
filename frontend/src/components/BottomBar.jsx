import { useContext } from 'react'
import { ThreatContext } from '../App.jsx'

function Dot({ color, glow }) {
    return (
        <span style={{
            display: 'inline-block',
            width: 6, height: 6, borderRadius: '50%',
            background: color,
            boxShadow: glow ? `0 0 6px ${color}` : 'none',
            flexShrink: 0,
        }} />
    )
}

function Item({ dot, dotColor, label, value, glow }) {
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {dot && <Dot color={dotColor} glow={glow} />}
            <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>
                {label}
            </span>
            <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text-secondary)', fontWeight: 600 }}>
                {value}
            </span>
        </div>
    )
}

export default function BottomBar({ status, eventCount }) {
    const { threatsBlocked } = useContext(ThreatContext)

    return (
        <footer style={{
            position: 'sticky',
            bottom: 0,
            zIndex: 40,
            background: 'rgba(6,8,15,0.9)',
            backdropFilter: 'blur(12px)',
            borderTop: '1px solid var(--border)',
            padding: '0 1.5rem',
            height: 34,
            display: 'flex',
            alignItems: 'center',
            gap: 24,
            flexShrink: 0,
        }}>
            <Item dot label="AGENT" value="v1.0.0" dotColor="#00FF94" glow />
            <span style={{ width: 1, height: 14, background: 'var(--border)' }} />
            <Item dot label="SYSMON" value="ACTIVE" dotColor="#00FF94" glow />
            <span style={{ width: 1, height: 14, background: 'var(--border)' }} />
            <Item dot label="SQLITE" value="WAL" dotColor="#00D4FF" glow />
            <span style={{ width: 1, height: 14, background: 'var(--border)' }} />
            <Item dot label="WINVERIFYTRUST" value="ACTIVE" dotColor="#00D4FF" glow />
            <span style={{ width: 1, height: 14, background: 'var(--border)' }} />
            <Item label="EVENTS" value={status?.total_events ?? 0} dotColor="#8899B0" />
            <span style={{ width: 1, height: 14, background: 'var(--border)' }} />
            <Item dot label="BLOCKED" value={threatsBlocked ?? status?.killed_processes ?? 0} dotColor="#FF2D55" glow />
            <div style={{ marginLeft: 'auto', fontFamily: '"JetBrains Mono"', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.06em' }}>
                BEHAVIORSHIELD · PFA DEMO · 2026
            </div>
        </footer>
    )
}
