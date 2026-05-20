import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

function truncate(str, n = 16) {
    if (!str) return '—'
    if (str.length <= n * 2 + 3) return str
    return str.slice(0, n) + '…' + str.slice(-n)
}

export default function Whitelist() {
    const [entries, setEntries] = useState([])
    const [loading, setLoading] = useState(true)
    const [removing, setRemoving] = useState({})
    const [adding, setAdding] = useState(false)
    const [addError, setAddError] = useState('')
    const fileInputRef = useRef(null)

    async function load() {
        try {
            const res = await axios.get('/api/whitelist')
            setEntries(res.data.whitelist || [])
        } catch { setEntries([]) }
        setLoading(false)
    }

    useEffect(() => { load() }, [])

    async function removeEntry(id) {
        setRemoving(r => ({ ...r, [id]: true }))
        setAddError('')
        try {
            await axios.delete(`/api/whitelist/${id}`)
            load()
        } catch (err) {
            console.error("Remove whitelist error:", err)
            setAddError('Failed to remove whitelist entry.')
        }
        setRemoving(r => ({ ...r, [id]: false }))
    }

    async function handleAddProgram() {
        setAdding(true)
        setAddError('')
        try {
            // Ask backend to open native dialog and get absolute path
            const res = await axios.get('/api/browse')
            const path = res.data.path
            
            if (!path) {
                setAdding(false)
                return // User canceled dialog
            }
            
            // Now we have the guaranteed absolute path, send it to whitelist
            await axios.post('/api/whitelist', { exe_path: path })
            load()
        } catch (err) {
            setAddError(err.response?.data?.error || 'Failed to add program')
        }
        setAdding(false)
    }

    const systemEntries = entries.filter(e => e.is_system)
    const userEntries = entries.filter(e => !e.is_system)

    const WhitelistTable = ({ items, title, subtitle, color }) => (
        <div style={{ marginBottom: 32 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 12 }}>
                <div>
                    <h3 style={{ fontFamily: 'Rajdhani', fontWeight: 700, fontSize: 13, color: color, letterSpacing: '0.1em', textTransform: 'uppercase', margin: 0 }}>
                        {title}
                    </h3>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{subtitle}</div>
                </div>
            </div>
            
            <div className="card" style={{ padding: 0, overflow: 'hidden', border: `1px solid ${color}22` }}>
                {items.length === 0 ? (
                    <div style={{ padding: '2rem', textAlign: 'center', fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)' }}>
                        No entries in this group.
                    </div>
                ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr>{['PROCESS NAME', 'SHA256', 'SOURCE', 'DATE', ''].map((h, i) => <th key={i} className="th" style={{ fontSize: 10 }}>{h}</th>)}</tr>
                        </thead>
                        <tbody>
                            {items.map(e => (
                                <tr key={`${e.id}-${e.added_date}`} className="tr-normal">
                                    <td className="td" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{e.process_name || '—'}</td>
                                    <td className="td" title={e.sha256} style={{ color: color, fontFamily: '"JetBrains Mono"', fontSize: 11 }}>{truncate(e.sha256, 8)}</td>
                                    <td className="td">
                                        <span style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
                                            {e.added_by || 'AGENT'}
                                        </span>
                                    </td>
                                    <td className="td" style={{ fontSize: 11 }}>{e.added_date?.slice(0, 10) || '—'}</td>
                                    <td className="td" style={{ textAlign: 'right' }}>
                                        {e.is_system ? (
                                            <div style={{ color: 'var(--text-muted)', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 6 }}>
                                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                                </svg>
                                                <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.05em' }}>PROTECTED</span>
                                            </div>
                                        ) : (
                                            <button className="btn-danger" style={{ padding: '3px 12px', fontSize: 10, borderRadius: 4 }}
                                                onClick={() => removeEntry(e.id)} disabled={removing[e.id]}>
                                                {removing[e.id] ? '…' : 'REMOVE'}
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    )

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 26, letterSpacing: '0.08em', color: 'var(--text-primary)' }}>
                        WHITELIST MANAGEMENT
                    </h1>
                    <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', marginTop: 2 }}>
                        TRUSTED CRYPTOGRAPHIC SIGNATURES — {entries.length} TOTAL ENTRIES
                    </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
                    <button 
                        className="btn-primary" 
                        onClick={handleAddProgram}
                        disabled={adding}
                        style={{ padding: '8px 16px', fontSize: 13, gap: 8 }}
                    >
                        {adding ? 'PROCESSING...' : '+ ADD PROGRAM'}
                    </button>
                    {addError && <div style={{ color: '#FF2D55', fontSize: 11, fontFamily: '"JetBrains Mono"', maxWidth: 300, textAlign: 'right' }}>{addError}</div>}
                </div>
            </div>

            {loading ? (
                <div className="card" style={{ padding: 40, textAlign: 'center' }}>
                    <div className="skeleton" style={{ height: 20, width: '40%', margin: '0 auto 10px' }} />
                    <div className="skeleton" style={{ height: 20, width: '60%', margin: '0 auto' }} />
                </div>
            ) : (
                <>
                    <WhitelistTable 
                        items={systemEntries} 
                        title="Group 1 — System Trusted (Auto)" 
                        subtitle="Automatically verified by BehaviorShield via Authenticode digital signatures. Read-only."
                        color="#00FF94"
                    />

                    <WhitelistTable 
                        items={userEntries} 
                        title="Group 2 — User Trusted (Manual)" 
                        subtitle="Processes you have manually whitelisted or restored from quarantine. Full control."
                        color="#00D4FF"
                    />
                </>
            )}
        </div>
    )
}
