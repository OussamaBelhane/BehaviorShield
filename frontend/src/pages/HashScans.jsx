import { useState, useEffect } from 'react'
import axios from 'axios'

export default function HashScans() {
    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)

    async function load() {
        try {
            const res = await axios.get('/api/hash-results')
            setScans(res.data || [])
        } catch { setScans([]) }
        setLoading(false)
    }

    useEffect(() => { load() }, [])

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div>
                <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 26, letterSpacing: '0.08em', color: 'var(--text-primary)' }}>
                    THREAT INTEL
                </h1>
                <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', marginTop: 2 }}>
                    PROCESS HASH SCANS — {scans.length} ENTRIES
                </div>
            </div>

            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                {loading ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <div className="skeleton" style={{ height: 20, width: '60%', margin: '0 auto 12px' }} />
                        <div className="skeleton" style={{ height: 20, width: '80%', margin: '0 auto 12px' }} />
                        <div className="skeleton" style={{ height: 20, width: '70%', margin: '0 auto' }} />
                    </div>
                ) : scans.length === 0 ? (
                    <div style={{ padding: '4rem', textAlign: 'center' }}>
                        <div style={{ marginBottom: 12 }}>
                            {/* Lucide search style SVG */}
                            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#00D4FF" strokeWidth="1.5" style={{ display: 'inline-block' }}>
                                <circle cx="11" cy="11" r="8" />
                                <path d="M21 21L16.65 16.65" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                        </div>
                        <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: 18, color: '#00D4FF', letterSpacing: '0.08em' }}>
                            No hash scans recorded yet
                        </div>
                    </div>
                ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr>
                                <th className="th">TIME</th>
                                <th className="th">PROCESS</th>
                                <th className="th">SHA-256</th>
                                <th className="th">RESULT</th>
                                <th className="th">SOURCE</th>
                                <th className="th">VT SCORE</th>
                            </tr>
                        </thead>
                        <tbody>
                            {scans.map(scan => (
                                <tr key={`${scan.id}-${scan.scanned_at}`} className="tr-normal">
                                    <td className="td" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                                        {scan.scanned_at?.slice(11, 19) || '—'}
                                    </td>
                                    <td className="td" style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }} title={scan.exe_path}>
                                        {scan.exe_path?.split('\\').pop() || scan.exe_path || '—'}
                                    </td>
                                    <td className="td" style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)' }} title={scan.sha256}>
                                        {scan.sha256 ? `${scan.sha256.substring(0, 16)}...` : '—'}
                                    </td>
                                    <td className="td">
                                        <span style={{
                                            fontFamily: '"JetBrains Mono"', fontWeight: 700,
                                            color: scan.result === 'malware' ? '#FF2D55' : scan.result === 'clean' ? '#00FF94' : '#FFB800'
                                        }}>
                                            {scan.result?.toUpperCase() || 'UNKNOWN'}
                                        </span>
                                    </td>
                                    <td className="td" style={{ textTransform: 'uppercase', fontSize: 11 }}>
                                        {scan.source || '—'}
                                    </td>
                                    <td className="td" style={{ fontFamily: '"JetBrains Mono"', fontWeight: 700, color: 'var(--text-primary)' }}>
                                        {scan.vt_score || '—'}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    )
}
