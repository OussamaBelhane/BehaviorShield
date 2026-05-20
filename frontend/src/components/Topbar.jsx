import { useEffect, useState, useContext } from 'react'
import { ThreatContext } from '../App.jsx'

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
        <span className="chip chip-cyan" style={{ letterSpacing: '0.1em', fontSize: 11 }}>
            <span style={{
                width: 6, height: 6, borderRadius: '50%',
                background: '#00D4FF',
                display: 'inline-block',
                animation: 'blink 1.2s step-start infinite',
            }} />
            {time}
        </span>
    )
}

export default function Topbar() {
    const { disconnected } = useContext(ThreatContext)

    return (
        <header style={{
            position: 'sticky',
            top: 0,
            zIndex: 40,
            background: 'rgba(6,8,15,0.85)',
            backdropFilter: 'blur(16px)',
            borderBottom: '1px solid var(--border)',
            padding: '0 1.5rem',
            height: 56,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexShrink: 0,
        }}>
            {/* Brand */}
            <div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 0 }}>
                    <span style={{
                        fontFamily: 'Rajdhani, sans-serif',
                        fontWeight: 700,
                        fontSize: 22,
                        color: 'var(--text-primary)',
                        letterSpacing: '0.08em',
                    }}>BEHAVIOR</span>
                    <span style={{
                        fontFamily: 'Rajdhani, sans-serif',
                        fontWeight: 700,
                        fontSize: 22,
                        color: '#00D4FF',
                        letterSpacing: '0.08em',
                        textShadow: '0 0 20px rgba(0,212,255,0.5)',
                    }}>SHIELD</span>
                </div>
                <div style={{
                    fontFamily: '"JetBrains Mono", monospace',
                    fontSize: 10,
                    color: 'var(--text-muted)',
                    letterSpacing: '0.12em',
                    marginTop: -2,
                }}>
                    ENDPOINT DETECTION SYSTEM
                </div>
            </div>

            {/* Status chips */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {disconnected ? (
                    <span className="chip chip-red">
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#FF2D55', animation: 'pulseDot 1s infinite', display: 'inline-block' }} />
                        DISCONNECTED
                    </span>
                ) : (
                    <>
                        <span className="chip chip-green">
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00FF94', display: 'inline-block', animation: 'pulseDot 2s ease-in-out infinite' }} />
                            SYSMON ACTIVE
                        </span>
                        <span className="chip chip-green">
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00FF94', display: 'inline-block', animation: 'pulseDot 2s ease-in-out infinite 0.5s' }} />
                            AGENT RUNNING
                        </span>
                    </>
                )}
                <ClockChip />
            </div>
        </header>
    )
}
