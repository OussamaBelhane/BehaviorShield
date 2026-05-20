import { NavLink } from 'react-router-dom'
import { useContext } from 'react'
import { ThreatContext } from '../App.jsx'

const ShieldSVG = () => (
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
        <path
            d="M18 3L5 8V18C5 25.7 10.7 32.9 18 35C25.3 32.9 31 25.7 31 18V8L18 3Z"
            stroke="#00D4FF" strokeWidth="1.5" fill="rgba(0,212,255,0.08)"
        />
        <path d="M12 18L16 22L24 14" stroke="#00FF94" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
)

const NAV = [
    { to: '/', icon: DashIcon, label: 'Dashboard' },
    { to: '/alerts', icon: AlertIcon, label: 'Alerts' },
    { to: '/quarantine', icon: LockIcon, label: 'Quarantine' },
    { to: '/whitelist', icon: ShieldCheck, label: 'Whitelist' },
    { to: '/hash-scans', icon: ScanIcon, label: 'Threat Intel' },
    { to: '/reports', icon: DocIcon, label: 'Reports' },
]

function ScanIcon() {
    return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21L16.65 16.65" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    )
}

function DashIcon() {
    return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
            <rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
        </svg>
    )
}
function AlertIcon() {
    return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" strokeLinejoin="round" />
        </svg>
    )
}
function LockIcon() {
    return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <rect x="5" y="11" width="14" height="10" rx="2" />
            <path d="M8 11V7a4 4 0 018 0v4" />
        </svg>
    )
}
function ShieldCheck() {
    return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M12 2L4 6V12C4 16.4 7.6 20.5 12 22C16.4 20.5 20 16.4 20 12V6L12 2Z" />
            <path d="M9 12L11 14L15 10" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    )
}
function DocIcon() {
    return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8L14 2Z" />
            <path d="M14 2v6h6M8 13h8M8 17h5" />
        </svg>
    )
}

function SettingsIcon() {
    return (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M12.22 2h-.44a2 2 0 00-2 2v.18a2 2 0 01-1 1.73l-.43.25a2 2 0 01-2 0l-.15-.08a2 2 0 00-2.73.73l-.22.38a2 2 0 00.73 2.73l.15.1a2 2 0 011 1.72v.51a2 2 0 01-1 1.74l-.15.09a2 2 0 00-.73 2.73l.22.38a2 2 0 002.73.73l.15-.08a2 2 0 012 0l.43.25a2 2 0 011 1.73V20a2 2 0 002 2h.44a2 2 0 002-2v-.18a2 2 0 011-1.73l.43-.25a2 2 0 012 0l.15.08a2 2 0 002.73-.73l.22-.39a2 2 0 00-.73-2.73l-.15-.08a2 2 0 01-1-1.74v-.5a2 2 0 011-1.74l.15-.09a2 2 0 00.73-2.73l-.22-.38a2 2 0 00-2.73-.73l-.15.08a2 2 0 01-2 0l-.43-.25a2 2 0 01-1-1.73V4a2 2 0 00-2-2z" />
            <circle cx="12" cy="12" r="3" />
        </svg>
    )
}

export default function Sidebar() {
    const { threatActive, activeAlerts, setSettingsOpen } = useContext(ThreatContext)
    const isProtected = !threatActive

    return (
        <aside
            style={{
                width: 70,
                minWidth: 70,
                background: 'var(--bg-surface)',
                borderRight: '1px solid var(--border)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                position: 'fixed',
                top: 0, bottom: 0, left: 0,
                zIndex: 50,
                backdropFilter: 'blur(12px)',
            }}
        >
            {/* Logo */}
            <div style={{ padding: '18px 0 14px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <div style={{ filter: 'drop-shadow(0 0 10px rgba(0,212,255,0.5))' }}>
                    <ShieldSVG />
                </div>
            </div>

            <div style={{ height: 1, width: 40, background: 'var(--border)', marginBottom: 8 }} />

            {/* Nav */}
            <nav style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, paddingTop: 8 }}>
                {NAV.map(({ to, icon: Icon, label }) => (
                    <NavLink
                        key={to}
                        to={to}
                        end={to === '/'}
                        style={({ isActive }) => ({
                            position: 'relative',
                            width: 44,
                            height: 44,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            borderRadius: 10,
                            color: isActive ? '#00D4FF' : 'var(--text-muted)',
                            background: isActive ? 'rgba(0,212,255,0.08)' : 'transparent',
                            borderLeft: isActive ? '3px solid #00D4FF' : '3px solid transparent',
                            transition: 'all 0.2s',
                            textDecoration: 'none',
                        })}
                        className="group"
                    >
                        {({ isActive }) => (
                            <>
                                <Icon />
                                {/* Alerts badge */}
                                {label === 'Alerts' && activeAlerts > 0 && (
                                    <span style={{
                                        position: 'absolute', top: 7, right: 7,
                                        width: 8, height: 8, borderRadius: '50%',
                                        background: '#FF2D55',
                                        boxShadow: '0 0 6px #FF2D55',
                                        animation: 'pulseDot 1.5s ease-in-out infinite',
                                    }} />
                                )}
                                {/* Tooltip */}
                                <span style={{
                                    position: 'absolute',
                                    left: 54,
                                    background: 'var(--bg-card)',
                                    border: '1px solid var(--border)',
                                    color: isActive ? '#00D4FF' : 'var(--text-primary)',
                                    fontFamily: '"JetBrains Mono", monospace',
                                    fontSize: 11,
                                    padding: '4px 10px',
                                    borderRadius: 6,
                                    whiteSpace: 'nowrap',
                                    pointerEvents: 'none',
                                    opacity: 0,
                                    transition: 'opacity 0.15s',
                                    zIndex: 100,
                                }} className="sidebar-tooltip">
                                    {label}
                                </span>
                            </>
                        )}
                    </NavLink>
                ))}
            </nav>

            {/* Bottom status & Settings */}
            <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 16,
                paddingBottom: 18,
            }}>
                <button
                    onClick={() => setSettingsOpen?.(true)}
                    style={{
                        background: 'transparent', border: 'none', color: 'var(--text-muted)',
                        cursor: 'pointer', padding: 8, borderRadius: 8,
                        transition: 'color 0.2s, background 0.2s'
                    }}
                    className="group"
                    title="Settings"
                >
                    <SettingsIcon />
                </button>

                <div style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6
                }}>
                    <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: isProtected ? '#00FF94' : '#FF2D55',
                        boxShadow: isProtected ? '0 0 10px #00FF94' : '0 0 10px #FF2D55',
                        animation: 'pulseDot 2s ease-in-out infinite',
                    }} />
                    <span style={{
                        fontFamily: '"JetBrains Mono", monospace',
                        fontSize: 9,
                        fontWeight: 700,
                        color: isProtected ? '#00FF94' : '#FF2D55',
                        letterSpacing: '0.12em',
                        writingMode: 'vertical-rl',
                        textOrientation: 'mixed',
                        transform: 'rotate(180deg)',
                        textTransform: 'uppercase',
                    }}>
                        {isProtected ? 'PROTECTED' : 'THREAT'}
                    </span>
                </div>
            </div>


            <style>{`
        .group:hover .sidebar-tooltip { opacity: 1 !important; }
        .group:hover { color: #E8EDF5 !important; background: rgba(0,212,255,0.04) !important; }
      `}</style>
        </aside >
    )
}
