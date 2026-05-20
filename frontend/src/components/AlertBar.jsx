import { useContext } from 'react'
import { ThreatContext } from '../App.jsx'

export default function AlertBar() {
    const { threatActive, latestThreat, dismissThreat } = useContext(ThreatContext)

    return (
        <div style={{
            overflow: 'hidden',
            maxHeight: threatActive ? 64 : 0,
            transition: 'max-height 0.35s cubic-bezier(0.4,0,0.2,1)',
            flexShrink: 0,
        }}>
            <div style={{
                height: 56,
                background: 'linear-gradient(90deg, rgba(255,45,85,0.25) 0%, rgba(255,45,85,0.10) 50%, rgba(255,45,85,0.06) 100%)',
                borderBottom: '1px solid rgba(255,45,85,0.35)',
                display: 'flex',
                alignItems: 'center',
                gap: '1.5rem',
                padding: '0 1.5rem',
            }}>
                {/* Kill badge */}
                <div style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    background: 'rgba(255,45,85,0.15)',
                    border: '1px solid rgba(255,45,85,0.4)',
                    borderRadius: 999,
                    padding: '4px 14px',
                    animation: 'pulseDot 1s ease-in-out infinite',
                    flexShrink: 0,
                }}>
                    <span style={{ fontSize: 14 }}>⚡</span>
                    <span style={{
                        fontFamily: 'Rajdhani, sans-serif',
                        fontWeight: 700,
                        fontSize: 13,
                        color: '#FF2D55',
                        letterSpacing: '0.1em',
                    }}>THREAT KILLED</span>
                </div>

                {/* Process info */}
                <div style={{ flex: 1, overflow: 'hidden' }}>
                    <span style={{
                        fontFamily: '"JetBrains Mono", monospace',
                        fontSize: 12,
                        color: 'var(--text-primary)',
                    }}>
                        <span style={{ color: '#FF2D55', fontWeight: 600 }}>
                            {latestThreat?.process_name || 'Unknown Process'}
                        </span>
                        {' '}&nbsp;·&nbsp;{' '}
                        <span style={{ color: 'var(--text-secondary)' }}>PID</span>{' '}
                        <span style={{ color: 'var(--text-primary)' }}>{latestThreat?.pid || '—'}</span>
                        {' '}&nbsp;·&nbsp;{' '}
                        <span style={{ color: 'var(--text-secondary)' }}>SCORE</span>{' '}
                        <span style={{ color: '#FF2D55', fontWeight: 700 }}>{latestThreat?.score ?? '—'}</span>
                    </span>
                </div>

                {/* Dismiss */}
                <button
                    onClick={dismissThreat}
                    style={{
                        background: 'rgba(255,45,85,0.12)',
                        border: '1px solid rgba(255,45,85,0.3)',
                        color: '#FF2D55',
                        borderRadius: 8,
                        padding: '4px 14px',
                        fontFamily: '"JetBrains Mono", monospace',
                        fontSize: 11,
                        cursor: 'pointer',
                        letterSpacing: '0.06em',
                        flexShrink: 0,
                    }}
                >
                    DISMISS ×
                </button>
            </div>
        </div>
    )
}
