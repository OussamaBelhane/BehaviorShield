import { useState, useEffect } from 'react'
import axios from 'axios'

function Switch({ checked, onChange }) {
    return (
        <label style={{
            position: 'relative', display: 'inline-block', width: 44, height: 24, cursor: 'pointer'
        }}>
            <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} style={{ opacity: 0, width: 0, height: 0 }} />
            <span style={{
                position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
                backgroundColor: checked ? 'rgba(0, 255, 148, 0.2)' : 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${checked ? '#00FF94' : 'rgba(255,255,255,0.2)'}`,
                transition: '.3s',
                borderRadius: 24
            }}></span>
            <span style={{
                position: 'absolute', height: 16, width: 16, left: 4, bottom: 3,
                backgroundColor: checked ? '#00FF94' : '#fff',
                transition: '.3s',
                transform: checked ? 'translateX(20px)' : 'none',
                borderRadius: '50%'
            }}></span>
        </label>
    )
}

export default function SettingsModal({ onClose }) {
    const [enabled, setEnabled] = useState(false)
    const [days, setDays] = useState(7)
    const [whitelistEnabled, setWhitelistEnabled] = useState(true)
    const [protectedFolders, setProtectedFolders] = useState([])
    const [saving, setSaving] = useState(false)

    useEffect(() => {
        axios.get('/api/status').then(res => {
            setEnabled(res.data.learning_mode)
            setDays(res.data.active_days || 7)
        }).catch(err => console.error(err))

        axios.get('/api/settings/whitelist-toggle').then(res => {
            setWhitelistEnabled(res.data.enabled)
        }).catch(err => console.error(err))

        fetchFolders()
    }, [])

    const fetchFolders = async () => {
        try {
            const res = await axios.get('/api/settings/folders')
            setProtectedFolders(res.data.folders || [])
        } catch (err) { console.error(err) }
    }

    const handleAddFolder = async () => {
        try {
            const res = await axios.get('/api/browse-folder')
            if (res.data.path) {
                await axios.post('/api/settings/folders', { path: res.data.path })
                fetchFolders()
            }
        } catch (err) {
            console.error(err)
            alert(err.response?.data?.error || "Failed to add folder")
        }
    }

    const handleRemoveFolder = async (id) => {
        try {
            await axios.delete(`/api/settings/folders/${id}`)
            fetchFolders()
        } catch (err) { console.error(err) }
    }

    const handleSave = async () => {
        setSaving(true)
        try {
            await axios.post('/api/settings/learning', { enabled, days })
            await axios.post('/api/settings/whitelist-toggle', { enabled: whitelistEnabled })
            onClose()
        } catch (err) {
            console.error(err)
            alert("Failed to save settings.")
        }
        setSaving(false)
    }

    return (
        <div style={{
            position: 'fixed', inset: 0, zIndex: 9999,
            background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(10px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
            <div className="card" style={{ width: 480, padding: 30, position: 'relative', maxHeight: '90vh', overflowY: 'auto' }}>
                <h2 style={{ margin: '0 0 20px 0', fontFamily: 'Rajdhani', fontSize: 24, letterSpacing: '0.1em' }}>AGENT SETTINGS</h2>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    {/* Learning Mode */}
                    <div style={{ background: 'rgba(255,255,255,0.02)', padding: 20, borderRadius: 8, border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4 }}>Learning Mode</div>
                                <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                                    Observe activity without killing processes.
                                </div>
                            </div>
                            <Switch checked={enabled} onChange={setEnabled} />
                        </div>

                        {enabled && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
                                <div style={{ fontSize: 14 }}>Duration (Days)</div>
                                <select
                                    value={days}
                                    onChange={e => setDays(Number(e.target.value))}
                                    style={{
                                        background: 'var(--bg-deep)', color: '#fff',
                                        border: '1px solid var(--border)', padding: '6px 12px',
                                        borderRadius: 6, fontFamily: '"JetBrains Mono"', fontSize: 13,
                                        outline: 'none', cursor: 'pointer'
                                    }}
                                >
                                    <option value={1}>1 Day</option>
                                    <option value={2}>2 Days</option>
                                    <option value={7}>1 Week</option>
                                    <option value={14}>2 Weeks</option>
                                    <option value={30}>1 Month</option>
                                </select>
                            </div>
                        )}
                    </div>

                    {/* Whitelist Toggle */}
                    <div style={{ background: 'rgba(255,255,255,0.02)', padding: 20, borderRadius: 8, border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4 }}>Enforce Whitelist</div>
                                <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                                    Skip monitoring for trusted/signed processes.
                                </div>
                            </div>
                            <Switch checked={whitelistEnabled} onChange={setWhitelistEnabled} />
                        </div>
                    </div>

                    {/* Protected Folders */}
                    <div style={{ background: 'rgba(255,255,255,0.02)', padding: 20, borderRadius: 8, border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4 }}>Protected Folders</div>
                                <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                                    Additional paths for Watchdog monitoring.
                                </div>
                            </div>
                            <button 
                                onClick={handleAddFolder}
                                style={{
                                    background: 'rgba(0,255,148,0.1)', border: '1px solid rgba(0,255,148,0.3)',
                                    color: '#00FF94', padding: '6px 12px', borderRadius: 4, cursor: 'pointer',
                                    fontSize: 12, fontWeight: 600
                                }}
                            >
                                ADD FOLDER
                            </button>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            {protectedFolders.length === 0 && (
                                <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.2)', fontStyle: 'italic' }}>
                                    No custom folders added.
                                </div>
                            )}
                            {protectedFolders.map(f => (
                                <div key={f.id} style={{
                                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                    background: 'rgba(255,255,255,0.03)', padding: '6px 10px', borderRadius: 4,
                                    border: '1px solid rgba(255,255,255,0.05)'
                                }}>
                                    <div style={{ fontSize: 12, fontFamily: '"JetBrains Mono"', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 300 }}>
                                        {f.path}
                                    </div>
                                    <button 
                                        onClick={() => handleRemoveFolder(f.id)}
                                        style={{ background: 'transparent', border: 'none', color: '#FF2D55', cursor: 'pointer', padding: 4, fontSize: 14 }}
                                    >
                                        ×
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 24 }}>
                    <button onClick={onClose} style={{
                        background: 'transparent', border: '1px solid var(--border)',
                        color: 'var(--text-muted)', padding: '8px 16px', borderRadius: 6, cursor: 'pointer'
                    }}>Cancel</button>

                    <button onClick={handleSave} disabled={saving} style={{
                        background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.3)',
                        color: '#00D4FF', padding: '8px 16px', borderRadius: 6, cursor: 'pointer',
                        fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8
                    }}>
                        {saving ? 'Saving...' : 'Save Settings'}
                    </button>
                </div>
            </div>
        </div>
    )
}
