import { useState, useContext } from 'react'
import axios from 'axios'
import { ThreatContext } from '../App.jsx'

function ScoreBadge({ score }) {
    if (score === 100) {
        return (
            <div style={{
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 800, letterSpacing: '0.05em',
                fontSize: 18, padding: '4px 6px', borderRadius: '6px', background: 'rgba(255,45,85,0.15)', color: '#FF2D55',
                border: '1px solid rgba(255,45,85,0.4)', textAlign: 'center', alignSelf: 'center', marginTop: 4, display: 'inline-block'
            }}>HASH</div>
        )
    }
    const color = score >= 60 ? '#FF2D55' : score >= 30 ? '#FFB800' : '#00D4FF'
    return (
        <div style={{
            fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
            fontSize: 42, lineHeight: 1, color,
            textShadow: `0 0 20px ${color}60`,
        }}>{score}</div>
    )
}

function StatusBadge({ alert }) {
    if (alert.dismissed) return <span className="badge-info">DISMISSED</span>
    if (alert.alert_type?.includes('KILL')) return <span className="badge-critical">KILLED</span>
    return <span className="badge-warning">ACTIVE</span>
}

const TABS = ['All', 'Active', 'Dismissed']

export default function Alerts() {
    const { alerts, refetch } = useContext(ThreatContext)
    const [tab, setTab] = useState('All')
    const [loading, setLoading] = useState({})
    const [error, setError] = useState('')
    
    const [dismissedIds, setDismissedIds] = useState(() => {
        try {
            return JSON.parse(localStorage.getItem('bs_dismissed_ids') || '[]')
        } catch { return [] }
    })

    const filtered = alerts.filter(a => {
        if (dismissedIds.includes(a.id)) return false
        if (tab === 'Active') return !a.dismissed
        if (tab === 'Dismissed') return a.dismissed
        return true
    })

    // Grouping logic: Group consecutive identical alerts
    const grouped = []
    filtered.forEach(alert => {
        const lastGroup = grouped[grouped.length - 1]
        const isSame = lastGroup && 
                      lastGroup.process_name === alert.process_name && 
                      lastGroup.message === alert.message &&
                      lastGroup.dismissed === alert.dismissed

        if (isSame) {
            lastGroup.ids.push(alert.id)
            if (alert.pid) lastGroup.allPids.add(alert.pid)
            lastGroup.count += 1
            lastGroup.endTime = alert.timestamp
        } else {
            grouped.push({
                ...alert,
                ids: [alert.id],
                allPids: new Set(alert.pid ? [alert.pid] : []),
                count: 1,
                startTime: alert.timestamp,
                endTime: alert.timestamp
            })
        }
    })

    async function dismiss(id) {
        setLoading(l => ({ ...l, [id]: true }))
        const newDismissed = [...dismissedIds, id]
        setDismissedIds(newDismissed)
        localStorage.setItem('bs_dismissed_ids', JSON.stringify(newDismissed))

        try {
            await axios.post(`/api/alerts/${id}/dismiss`)
            refetch()
        } catch (err) {
            setError('Failed to dismiss alert.')
            setDismissedIds(prev => prev.filter(i => i !== id))
        }
        setLoading(l => ({ ...l, [id]: false }))
    }

    async function dismissGroup(ids) {
        const groupId = ids.join('-')
        setLoading(l => ({ ...l, [groupId]: true }))
        
        // Optimistic update
        const newDismissed = [...dismissedIds, ...ids]
        setDismissedIds(newDismissed)
        localStorage.setItem('bs_dismissed_ids', JSON.stringify(newDismissed))

        try {
            // Dismiss all sequentially
            for (const id of ids) {
                await axios.post(`/api/alerts/${id}/dismiss`)
            }
            refetch()
        } catch (err) {
            setError('Bulk dismiss partially failed.')
        }
        setLoading(l => ({ ...l, [groupId]: false }))
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <div>
                    <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 28, letterSpacing: '0.08em', color: 'var(--text-primary)' }}>
                        ALERTS
                    </h1>
                    <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', marginTop: 2 }}>
                        THREAT TIMELINE — {filtered.length} RECORDS ({grouped.length} GROUPED)
                    </div>
                    {error && <div style={{ color: '#FF2D55', fontSize: 11, marginTop: 8 }}>⚠ {error}</div>}
                </div>

                <div style={{ display: 'flex', gap: 4, background: 'var(--bg-surface)', borderRadius: 10, padding: 4, border: '1px solid var(--border)' }}>
                    {TABS.map(t => (
                        <button key={t} onClick={() => setTab(t)} style={{
                            fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: 13, padding: '6px 18px',
                            borderRadius: 7, border: 'none', cursor: 'pointer',
                            background: tab === t ? 'rgba(0,212,255,0.12)' : 'transparent',
                            color: tab === t ? '#00D4FF' : 'var(--text-muted)',
                        }}>{t.toUpperCase()}</button>
                    ))}
                </div>
            </div>

            {grouped.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '4rem 0', color: 'var(--text-muted)', fontFamily: '"JetBrains Mono"' }}>
                    No alerts found.
                </div>
            ) : grouped.map(g => {
                const isGroup = g.count > 1
                const groupId = g.ids.join('-')
                const pidsArr = Array.from(g.allPids)
                const pidDisplay = pidsArr.length > 2 
                    ? `${pidsArr[0]}...${pidsArr[pidsArr.length-1]}`
                    : pidsArr.join(', ') || '—'

                return (
                    <div key={groupId} className="card" style={{
                        display: 'flex', gap: 24, alignItems: 'flex-start',
                        borderLeft: g.dismissed ? '3px solid rgba(0,212,255,0.15)' : '3px solid #FF2D55',
                        marginBottom: 10,
                        background: 'linear-gradient(145deg, var(--bg-card), rgba(255,255,255,0.01))',
                        boxShadow: '0 4px 20px rgba(0,0,0,0.2)',
                        transition: 'transform 0.2s',
                    }}>
                        {/* Score Badge */}
                        <div style={{ textAlign: 'center', minWidth: 80 }}>
                            <div style={{ 
                                background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: 12, 
                                border: '1px solid rgba(255,255,255,0.03)' 
                            }}>
                                <ScoreBadge score={g.score} />
                            </div>
                            <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 9, color: 'var(--text-muted)', marginTop: 8 }}>SCORE</div>
                        </div>

                        {/* Content */}
                        <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                                <span style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 19, color: 'var(--text-primary)' }}>
                                    {g.process_name || g.alert_type}
                                </span>
                                {isGroup && (
                                    <span style={{ 
                                        background: 'rgba(255,45,85,0.15)', color: '#FF2D55', 
                                        fontSize: 11, padding: '2px 8px', borderRadius: 6, fontWeight: 800,
                                        fontFamily: 'Rajdhani'
                                    }}>
                                        ×{g.count}
                                    </span>
                                )}
                                <StatusBadge alert={g} />
                            </div>

                            <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
                                PID <span style={{ color: 'var(--text-secondary)' }}>{pidDisplay}</span>
                                &nbsp;·&nbsp;
                                {g.startTime?.slice(11, 19)} 
                                {isGroup && ` → ${g.endTime?.slice(11, 19)}`}
                                &nbsp;·&nbsp;
                                {g.startTime?.slice(0, 10)}
                            </div>

                            <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                                {g.message}
                            </div>
                        </div>

                        {/* Actions */}
                        {!g.dismissed && (
                            <div style={{ alignSelf: 'center' }}>
                                {isGroup ? (
                                    <button className="btn-primary" onClick={() => dismissGroup(g.ids)} disabled={loading[groupId]}
                                        style={{ fontSize: 10, padding: '6px 12px' }}>
                                        {loading[groupId] ? '…' : 'DISMISS ALL'}
                                    </button>
                                ) : (
                                    <button className="btn-ghost" onClick={() => dismiss(g.id)} disabled={loading[g.id]}
                                        style={{ fontSize: 11 }}>
                                        {loading[g.id] ? '…' : 'DISMISS'}
                                    </button>
                                )}
                            </div>
                        )}
                    </div>
                )
            })}
        </div>
    )
}
