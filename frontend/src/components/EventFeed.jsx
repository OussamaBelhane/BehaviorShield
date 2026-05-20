import { useState, useEffect, useRef } from 'react'

/**
 * Coloured dot indicator for severity — only shown for WARNING / CRITICAL.
 * INFO rows don't need a visual indicator; the dot column is removed entirely.
 */
function SeverityDot({ sev }) {
    if (sev === 'CRITICAL') return (
        <span title="CRITICAL" style={{
            display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
            background: '#FF2D55', boxShadow: '0 0 6px #FF2D55', flexShrink: 0,
        }} />
    )
    if (sev === 'WARNING') return (
        <span title="WARNING" style={{
            display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
            background: '#FFB800', boxShadow: '0 0 6px #FFB800', flexShrink: 0,
        }} />
    )
    return <span style={{ display: 'inline-block', width: 8, height: 8 }} /> // empty placeholder
}

function ScoreCell({ event }) {
    const delta = event.score_delta || 0
    const total = event.process_score || 0
    if (total === 0 && delta === 0)
        return <span style={{ color: 'var(--text-muted)', fontFamily: '"JetBrains Mono"', fontSize: 12 }}>—</span>

    const color = total >= 60 ? '#FF2D55' : total >= 30 ? '#FFB800' : delta > 0 ? '#ffb800' : 'var(--text-muted)'
    const shadow = total >= 60 ? '0 0 8px rgba(255,45,85,0.6)' : 'none'
    return (
        <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, fontWeight: 700, color, textShadow: shadow }}>
            {total > 0 ? total : (delta > 0 ? `+${delta}` : '—')}
        </span>
    )
}

function EventTypePill({ type }) {
    const COLOR_MAP = {
        CREATE: '#00D4FF',
        MODIFY: 'var(--text-muted)',
        RENAME: '#FFB800',
        DELETE: '#FF2D55',
    }
    const color = COLOR_MAP[type] || 'var(--text-muted)'
    return (
        <span style={{
            fontFamily: '"JetBrains Mono"', fontSize: 8, fontWeight: 700,
            color, letterSpacing: '0.08em', opacity: 0.8,
        }}>
            {type}
        </span>
    )
}

function truncatePath(path) {
    if (!path) return '—'
    const norm = path.replace(/\\/g, '/')
    const parts = norm.split('/')
    // Always show last 2 segments: …/folder/file.ext
    if (parts.length > 2) return '…/' + parts.slice(-2).join('/')
    return path
}

function ProcessCell({ e }) {
    const name = e.process_name || ''
    const pid = e.pid || 0
    const isSys = e.source === 'sysmon'

    const sourceBadge = (
        <span title={isSys ? 'Source: Sysmon (exact PID + name)' : 'Source: Watchdog (best-effort)'} style={{
            fontFamily: '"JetBrains Mono"', fontSize: 8, fontWeight: 700,
            letterSpacing: '0.06em',
            color: isSys ? '#00FF94' : 'var(--text-muted)',
            background: isSys ? 'rgba(0,255,148,0.1)' : 'rgba(255,255,255,0.05)',
            border: `1px solid ${isSys ? 'rgba(0,255,148,0.3)' : 'rgba(255,255,255,0.1)'}`,
            borderRadius: 3, padding: '0 4px',
        }}>
            {isSys ? 'SYS' : 'WD'}
        </span>
    )

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ color: name ? 'var(--text-primary)' : 'var(--text-muted)', fontWeight: name ? 600 : 400, fontStyle: name ? 'normal' : 'italic', fontSize: name ? 13 : 11 }}>
                    {name || 'Unknown'}
                </span>
                {sourceBadge}
            </div>
            {pid > 0 && (
                <span style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: '"JetBrains Mono"' }}>
                    PID {pid}
                </span>
            )}
        </div>
    )
}

const HEADERS = ['', 'TIME', 'PROCESS', 'ACTION · FILE PATH', 'SCORE']

export default function EventFeed({ events }) {
    const [rows, setRows] = useState([])
    const prevLen = useRef(0)

    useEffect(() => {
        if (!events || events.length === 0) return
        const newRows = events.map((e, i) => ({
            ...e,
            _new: i < (events.length - prevLen.current),
        }))
        prevLen.current = events.length
        setRows(newRows)
    }, [events])

    const critical = rows.filter(r => r.severity === 'CRITICAL').length
    const warning = rows.filter(r => r.severity === 'WARNING').length

    return (
        <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 400 }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
                <span style={{
                    fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
                    fontSize: 15, letterSpacing: '0.12em', color: 'var(--text-primary)',
                }}>LIVE EVENT FEED</span>

                <span style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    background: 'rgba(0,255,148,0.08)', border: '1px solid rgba(0,255,148,0.2)',
                    borderRadius: 999, padding: '2px 10px',
                }}>
                    <span style={{
                        width: 6, height: 6, borderRadius: '50%', background: '#00FF94',
                        animation: 'pulseDot 1.5s ease-in-out infinite', display: 'inline-block',
                    }} />
                    <span style={{ fontFamily: '"JetBrains Mono"', fontSize: 10, color: '#00FF94', letterSpacing: '0.08em' }}>LIVE</span>
                </span>

                {/* Severity summary badges — only when non-zero */}
                {critical > 0 && (
                    <span style={{
                        fontFamily: '"JetBrains Mono"', fontSize: 10, fontWeight: 700,
                        color: '#FF2D55', background: 'rgba(255,45,85,0.12)',
                        border: '1px solid rgba(255,45,85,0.3)', borderRadius: 999, padding: '2px 8px',
                    }}>{critical} CRITICAL</span>
                )}
                {warning > 0 && (
                    <span style={{
                        fontFamily: '"JetBrains Mono"', fontSize: 10, fontWeight: 700,
                        color: '#FFB800', background: 'rgba(255,184,0,0.10)',
                        border: '1px solid rgba(255,184,0,0.25)', borderRadius: 999, padding: '2px 8px',
                    }}>{warning} WARNING</span>
                )}

                <span style={{ marginLeft: 'auto', fontFamily: '"JetBrains Mono"', fontSize: 10, color: 'var(--text-muted)' }}>
                    {rows.length} events
                </span>
            </div>

            {/* Table */}
            <div style={{ flex: 1, overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            {HEADERS.map((h, i) => (
                                <th key={i} className="th" style={{
                                    position: 'sticky', top: 0, background: 'var(--bg-surface)', zIndex: 1,
                                    width: i === 0 ? 16 : undefined,
                                }}>
                                    {h}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {rows.length === 0 ? (
                            <tr>
                                <td colSpan={5} style={{ textAlign: 'center', padding: '3rem 0', fontFamily: '"JetBrains Mono"', fontSize: 12, color: 'var(--text-muted)' }}>
                                    Waiting for events…
                                </td>
                            </tr>
                        ) : rows.map((e, i) => {
                            const isCritical = e.severity === 'CRITICAL'
                            const isWarning = e.severity === 'WARNING'
                            const isNoise = !isCritical && !isWarning && (e.score_delta || 0) === 0

                            const rowClass = isCritical ? 'tr-danger' : isWarning ? 'tr-warning' : 'tr-normal'
                            const filePath = e.dest_path || e.source_path || ''

                            return (
                                <tr
                                    key={e.id ?? i}
                                    className={rowClass}
                                    style={{
                                        animation: e._new ? 'fadeUp 0.35s ease-out' : 'none',
                                        opacity: isNoise ? 0.55 : 1,
                                    }}
                                >
                                    {/* Severity dot */}
                                    <td className="td" style={{ padding: '6px 4px 6px 8px', width: 16 }}>
                                        <SeverityDot sev={e.severity} />
                                    </td>

                                    {/* Time */}
                                    <td className="td" style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap', width: 64 }}>
                                        {e.timestamp?.slice(11, 19) ?? '—'}
                                    </td>

                                    {/* Process */}
                                    <td className="td" style={{ maxWidth: 130, overflow: 'hidden' }}>
                                        <ProcessCell e={e} />
                                    </td>

                                    {/* Action · File Path */}
                                    <td
                                        className="td"
                                        style={{ maxWidth: 260, cursor: 'copy' }}
                                        title={filePath + (filePath ? ' — double-click to copy' : '')}
                                        onDoubleClick={() => { if (filePath) navigator.clipboard.writeText(filePath) }}
                                    >
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                            <span style={{
                                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                color: isCritical ? '#FF2D55' : isWarning ? '#FFB800' : 'var(--text-secondary)',
                                                fontSize: 12,
                                            }}>
                                                {truncatePath(filePath)}
                                            </span>
                                            <EventTypePill type={e.event_type} />
                                        </div>
                                    </td>

                                    {/* Score */}
                                    <td className="td"><ScoreCell event={e} /></td>
                                </tr>
                            )
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    )
}
