import { useContext } from 'react'
import { ThreatContext } from '../App.jsx'

function Ring({ delay, size }) {
    return (
        <div style={{
            position: 'absolute',
            width: size, height: size,
            borderRadius: '50%',
            border: '1.5px solid rgba(0,212,255,0.4)',
            top: '50%', left: '50%',
            transform: 'translate(-50%,-50%) scale(1)',
            animation: `ring-pulse 3s ease-out infinite ${delay}s`,
        }} />
    )
}

function CenterShield({ threatActive }) {
    return (
        <div style={{
            position: 'relative', zIndex: 2,
            animation: 'float 4s ease-in-out infinite',
            filter: threatActive
                ? 'drop-shadow(0 0 18px rgba(255,45,85,0.7))'
                : 'drop-shadow(0 0 14px rgba(0,212,255,0.5))',
        }}>
            <svg width="72" height="72" viewBox="0 0 72 72" fill="none">
                <path
                    d="M36 6L10 18V36C10 51.4 21.4 65.8 36 70C50.6 65.8 62 51.4 62 36V18L36 6Z"
                    stroke={threatActive ? '#FF2D55' : '#00D4FF'}
                    strokeWidth="2"
                    fill={threatActive ? 'rgba(255,45,85,0.08)' : 'rgba(0,212,255,0.06)'}
                />
                {threatActive ? (
                    <path d="M26 26L46 46M46 26L26 46" stroke="#FF2D55" strokeWidth="3" strokeLinecap="round" />
                ) : (
                    <path d="M24 36L32 44L48 28" stroke="#00FF94" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
                )}
            </svg>
        </div>
    )
}

const INFO_ROWS = [
    { label: 'UPTIME', key: 'uptime', fallback: '—' },
    { label: 'MODE', key: 'mode', fallback: 'PROTECTION' },
    { label: 'SYSMON', key: 'sysmon', fallback: 'ACTIVE' },
    { label: 'SQLITE WAL', key: 'sqlite', fallback: 'ENABLED' },
    { label: 'WINVERIFYTRUST', key: 'winverifytrust', fallback: 'ACTIVE' },
]

export default function ShieldCore({ status }) {
    const { threatActive, topScore } = useContext(ThreatContext)
    const score = topScore ?? 0
    const barColor = score >= 60 ? '#FF2D55' : score >= 30 ? '#FFB800' : '#00D4FF'
    const barPct = Math.min(score, 100)

    const formatUptime = (seconds) => {
        if (!seconds && seconds !== 0) return '00:00:00'
        const h = Math.floor(seconds / 3600).toString().padStart(2, '0')
        const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0')
        const s = (Math.floor(seconds) % 60).toString().padStart(2, '0')
        return `${h}:${m}:${s}`
    }

    const infoValues = {
        uptime: formatUptime(status?.uptime),
        mode: status?.learning_mode ? 'LEARNING' : 'PROTECTION',
        sysmon: 'ACTIVE',
        sqlite: 'WAL MODE',
        winverifytrust: 'ACTIVE',
    }

    return (
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
            {/* Rings + shield */}
            <div style={{ position: 'relative', width: 140, height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Ring size={140} delay={0} />
                <Ring size={110} delay={1} />
                <Ring size={80} delay={2} />
                {/* Glow backdrop */}
                <div style={{
                    position: 'absolute',
                    width: 70, height: 70,
                    borderRadius: '50%',
                    background: threatActive
                        ? 'radial-gradient(circle, rgba(255,45,85,0.15) 0%, transparent 70%)'
                        : 'radial-gradient(circle, rgba(0,212,255,0.12) 0%, transparent 70%)',
                }} />
                <CenterShield threatActive={threatActive} />
            </div>

            {/* Status text */}
            <div style={{
                fontFamily: 'Rajdhani, sans-serif',
                fontWeight: 700,
                fontSize: 18,
                letterSpacing: '0.15em',
                color: threatActive ? '#FF2D55' : '#00FF94',
                textShadow: threatActive ? '0 0 16px rgba(255,45,85,0.6)' : '0 0 12px rgba(0,255,148,0.5)',
                textTransform: 'uppercase',
            }}>
                {threatActive ? 'THREAT KILLED' : 'PROTECTED'}
            </div>

            {/* Score bar */}
            <div style={{ width: '100%' }}>
                <div style={{
                    display: 'flex', justifyContent: 'space-between', marginBottom: 6,
                }}>
                    <span style={{ fontFamily: '"JetBrains Mono"', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                        THREAT SCORE
                    </span>
                    <span style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: barColor, fontWeight: 700 }}>
                        {score}
                    </span>
                </div>
                <div style={{
                    height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)',
                    overflow: 'hidden',
                }}>
                    <div style={{
                        height: '100%',
                        width: `${barPct}%`,
                        borderRadius: 3,
                        background: barColor,
                        boxShadow: `0 0 8px ${barColor}80`,
                        transition: 'width 0.5s ease, background 0.5s ease',
                    }} />
                </div>
            </div>

            {/* Info rows */}
            <div style={{ width: '100%' }}>
                {INFO_ROWS.map(({ label, key }) => (
                    <div key={key} className="info-row">
                        <span className="info-label">{label}</span>
                        <span className="info-value">{infoValues[key]}</span>
                    </div>
                ))}
            </div>
        </div>
    )
}
