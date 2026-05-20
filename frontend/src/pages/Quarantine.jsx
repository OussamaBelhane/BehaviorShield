import { useState, useEffect } from 'react'
import axios from 'axios'

function Modal({ title, children, onClose }) {
    return (
        <div style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(6px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} onClick={onClose}>
            <div className="card" style={{ maxWidth: 460, width: '90%', padding: 28 }}
                onClick={e => e.stopPropagation()}>
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 18, letterSpacing: '0.08em', color: 'var(--text-primary)', marginBottom: 16 }}>
                    {title}
                </div>
                {children}
            </div>
        </div>
    )
}

export default function Quarantine() {
    const [items, setItems] = useState([])
    const [loading, setLoading] = useState(true)
    const [restoreTarget, setRestoreTarget] = useState(null)
    const [deleteTarget, setDeleteTarget] = useState(null)
    const [inspectTarget, setInspectTarget] = useState(null)
    const [inspectData, setInspectData] = useState(null)
    const [restoreWhitelist, setRestoreWhitelist] = useState(false)
    const [busy, setBusy] = useState(false)
    const [error, setError] = useState('')

    async function load() {
        try {
            const res = await axios.get('/api/quarantine')
            setItems(res.data.quarantine || [])
        } catch { setItems([]) }
        setLoading(false)
    }

    useEffect(() => { load() }, [])

    async function doRestore() {
        setBusy(true)
        setError('')
        try {
            await axios.post(`/api/quarantine/${restoreTarget.id}/restore`, { whitelist: restoreWhitelist })
            setRestoreTarget(null); load()
        } catch (err) {
            console.error("Restore error:", err)
            setError('Failed to restore file. The file might be in use or access was denied.')
        }
        setBusy(false)
    }

    async function doDelete() {
        setBusy(true)
        setError('')
        try {
            await axios.post(`/api/quarantine/${deleteTarget.id}/delete`)
            setDeleteTarget(null); load()
        } catch (err) {
            console.error("Delete error:", err)
            setError('Failed to delete file. Ensure BehaviorShield has appropriate permissions.')
        }
        setBusy(false)
    }

    async function doInspect(item) {
        setInspectTarget(item)
        setInspectData(null)
        try {
            const res = await axios.get(`/api/quarantine/${item.id}/inspect`)
            setInspectData(res.data)
        } catch { setInspectData({ error: 'Failed to load details' }) }
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div>
                <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 26, letterSpacing: '0.08em', color: 'var(--text-primary)' }}>
                    QUARANTINE
                </h1>
                <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', marginTop: 2 }}>
                    ISOLATED FILES — {items.length} ENTRIES
                </div>
                {error && (
                    <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: '#FF2D55', marginTop: 8 }}>
                        ⚠ {error}
                    </div>
                )}
            </div>

            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                {loading ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <div className="skeleton" style={{ height: 20, width: '60%', margin: '0 auto 12px' }} />
                        <div className="skeleton" style={{ height: 20, width: '80%', margin: '0 auto 12px' }} />
                        <div className="skeleton" style={{ height: 20, width: '70%', margin: '0 auto' }} />
                    </div>
                ) : items.length === 0 ? (
                    <div style={{ padding: '4rem', textAlign: 'center' }}>
                        <div style={{ marginBottom: 12 }}>
                            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#00FF94" strokeWidth="1.5" style={{ display: 'inline-block' }}>
                                <path d="M12 2L4 6V12C4 16.4 7.6 20.5 12 22C16.4 20.5 20 16.4 20 12V6L12 2Z" />
                                <path d="M9 12L11 14L15 10" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                        </div>
                        <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: 18, color: '#00FF94', letterSpacing: '0.08em' }}>
                            No files in quarantine — system is clean
                        </div>
                    </div>
                ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr>{['FILENAME', 'ORIGINAL PATH', 'REASON', 'DATE CAUGHT', 'STATUS', 'ACTIONS'].map(h => <th key={h} className="th">{h}</th>)}</tr>
                        </thead>
                        <tbody>
                            {items.map(item => (
                                <tr key={`${item.id}-${item.quarantined_at}`} className="tr-normal">
                                    <td className="td" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                                        {item.original_path?.split(/[\\/]/).pop() || '—'}
                                    </td>
                                    <td className="td" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-muted)', fontSize: 11 }} title={item.original_path}>
                                        {item.original_path || '—'}
                                    </td>
                                    <td className="td" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                                        {item.reason || 'Manual Quarantine'}
                                    </td>
                                    <td className="td" style={{ fontSize: 11 }}>
                                        {item.quarantined_at?.slice(0, 16).replace('T', ' ') || '—'}
                                    </td>
                                    <td className="td">
                                        <span style={{ 
                                            padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                                            background: item.status === 'QUARANTINED' ? 'rgba(255,45,85,0.1)' : 'rgba(0,255,148,0.1)',
                                            color: item.status === 'QUARANTINED' ? '#FF2D55' : '#00FF94'
                                        }}>
                                            {item.status}
                                        </span>
                                    </td>
                                    <td className="td" style={{ display: 'flex', gap: 6 }}>
                                        <button className="btn-ghost" style={{ padding: '4px 10px', fontSize: 10, borderColor: 'rgba(255,255,255,0.1)' }}
                                            onClick={() => doInspect(item)}>INSPECT</button>
                                        {item.status === 'QUARANTINED' && (
                                            <>
                                                <button className="btn-success" style={{ padding: '4px 10px', fontSize: 10 }}
                                                    onClick={() => { setRestoreTarget(item); setRestoreWhitelist(true) }}>RESTORE</button>
                                                <button className="btn-danger" style={{ padding: '4px 10px', fontSize: 10 }}
                                                    onClick={() => setDeleteTarget(item)}>DELETE</button>
                                            </>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {inspectTarget && (
                <Modal title="FILE INSPECTION" onClose={() => setInspectTarget(null)}>
                    {!inspectData ? (
                        <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>Loading artifact data...</div>
                    ) : inspectData.error ? (
                        <div style={{ color: '#FF2D55' }}>{inspectData.error}</div>
                    ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                            <div>
                                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>FILE SHA-256</div>
                                <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: '#00D4FF', wordBreak: 'break-all', background: 'rgba(0,0,0,0.2)', padding: 8, borderRadius: 4 }}>
                                    {inspectData.file_sha256}
                                </div>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                                <div>
                                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>VIRUSTOTAL</div>
                                    <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 13, fontWeight: 700, color: (inspectData.hash_info?.vt_score?.split('/')[0] > 0) ? '#FF2D55' : '#00FF94' }}>
                                        {inspectData.hash_info?.vt_score || 'N/A'}
                                    </div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>VERDICT</div>
                                    <div style={{ fontFamily: 'Rajdhani', fontSize: 13, fontWeight: 700, textTransform: 'uppercase', color: inspectData.hash_info?.result === 'malware' ? '#FF2D55' : '#00FF94' }}>
                                        {inspectData.hash_info?.result || 'UNKNOWN'}
                                    </div>
                                </div>
                            </div>

                            <div>
                                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 8 }}>TRIGGERED BEHAVIORS</div>
                                <div style={{ maxHeight: 120, overflowY: 'auto', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                                    {inspectData.triggered_events?.length > 0 ? (
                                        inspectData.triggered_events.map((e, idx) => (
                                            <div key={`${e.event_type}-${idx}`} style={{ padding: '6px 10px', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 11, display: 'flex', justifyContent: 'space-between' }}>
                                                <span style={{ color: '#FFB800' }}>{e.event_type}</span>
                                                <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{e.timestamp.slice(11, 19)}</span>
                                            </div>
                                        ))
                                    ) : (
                                        <div style={{ padding: 12, fontSize: 11, color: 'var(--text-muted)' }}>No direct file behaviors recorded.</div>
                                    )}
                                </div>
                            </div>

                            <button className="btn-ghost" onClick={() => setInspectTarget(null)} style={{ width: '100%', marginTop: 8 }}>CLOSE</button>
                        </div>
                    )}
                </Modal>
            )}

            {restoreTarget && (
                <Modal title="RESTORE FILE" onClose={() => setRestoreTarget(null)}>
                    <p style={{ fontFamily: '"JetBrains Mono"', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
                        Restore <span style={{ color: '#00D4FF' }}>{restoreTarget.original_path.split(/[\\/]/).pop()}</span> to original location?
                    </p>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, cursor: 'pointer' }}>
                        <input type="checkbox" checked={restoreWhitelist} onChange={e => setRestoreWhitelist(e.target.checked)} style={{ accentColor: '#00FF94' }} />
                        <span style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-secondary)' }}>
                            Also whitelist this hash (prevent re-quarantine)
                        </span>
                    </label>
                    <div style={{ display: 'flex', gap: 10 }}>
                        <button className="btn-success" onClick={doRestore} disabled={busy}>{busy ? 'RESTORING…' : 'RESTORE'}</button>
                        <button className="btn-ghost" onClick={() => setRestoreTarget(null)}>CANCEL</button>
                    </div>
                </Modal>
            )}

            {deleteTarget && (
                <Modal title="DELETE PERMANENTLY" onClose={() => setDeleteTarget(null)}>
                    <p style={{ fontFamily: '"JetBrains Mono"', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 20 }}>
                        Permanently delete <span style={{ color: '#FF2D55' }}>{deleteTarget.original_path.split(/[\\/]/).pop()}</span>?
                    </p>
                    <div style={{ display: 'flex', gap: 10 }}>
                        <button className="btn-danger" onClick={doDelete} disabled={busy}>{busy ? 'DELETING…' : 'DELETE PERMANENTLY'}</button>
                        <button className="btn-ghost" onClick={() => setDeleteTarget(null)}>CANCEL</button>
                    </div>
                </Modal>
            )}
        </div>
    )
}
