import { useState, useEffect } from 'react'
import axios from 'axios'
import { FileText, Download, Loader } from 'lucide-react'

export default function Reports() {
    const [fromDate, setFromDate] = useState('')
    const [toDate, setToDate] = useState('')
    const [loading, setLoading] = useState(false)
    const [reports, setReports] = useState([])
    const [reportsLoading, setReportsLoading] = useState(true)
    const [error, setError] = useState('')

    async function loadReports() {
        try {
            const res = await axios.get('/api/reports')
            setReports(res.data.reports || [])
        } catch { setReports([]) }
        setReportsLoading(false)
    }

    useEffect(() => { loadReports() }, [])

    async function generatePDF() {
        if (!fromDate || !toDate) { setError('Please select both From and To dates.'); return }
        setError(''); setLoading(true)
        try {
            const res = await axios.get('/api/reports/generate', {
                params: { from: fromDate, to: toDate },
                responseType: 'blob',
            })
            
            const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
            const a = document.createElement('a')
            a.href = url
            a.download = `BehaviorShield_Report_${fromDate}_${toDate}.pdf`
            a.click()
            URL.revokeObjectURL(url)
            loadReports()
        } catch (err) {
            console.error("PDF Error:", err)
            if (err.response && err.response.data instanceof Blob) {
                const reader = new FileReader()
                reader.onload = () => {
                    try {
                        const json = JSON.parse(reader.result)
                        setError(json.error || 'Failed to generate report.')
                    } catch {
                        setError('Failed to generate report (Invalid response format).')
                    }
                }
                reader.readAsText(err.response.data)
            } else {
                setError('Failed to generate report. Ensure the backend is running.')
            }
        }
        setLoading(false)
    }

    const inputStyle = {
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '8px 14px', color: 'var(--text-primary)',
        fontFamily: '"JetBrains Mono", monospace', fontSize: 12,
        colorScheme: 'dark', outline: 'none', transition: 'border-color 0.2s',
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 700 }}>
            <div>
                <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 26, letterSpacing: '0.08em', color: 'var(--text-primary)' }}>
                    REPORTS
                </h1>
                <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', marginTop: 2 }}>
                    PDF THREAT REPORTS
                </div>
            </div>

            {/* Generator card */}
            <div className="card">
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 15, letterSpacing: '0.1em', color: 'var(--text-primary)', marginBottom: 20 }}>
                    GENERATE NEW REPORT
                </div>
                <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <div>
                        <label style={{ fontFamily: '"JetBrains Mono"', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>FROM DATE</label>
                        <input type="date" value={fromDate} onChange={e => setFromDate(e.target.value)} style={inputStyle} />
                    </div>
                    <div>
                        <label style={{ fontFamily: '"JetBrains Mono"', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>TO DATE</label>
                        <input type="date" value={toDate} onChange={e => setToDate(e.target.value)} style={inputStyle} />
                    </div>
                    <button className="btn-primary" onClick={generatePDF} disabled={loading}
                        style={{ height: 38, minWidth: 190, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                        {loading
                            ? <><Loader size={14} style={{ animation: 'spin 0.8s linear infinite' }} /> GENERATING…</>
                            : <><FileText size={14} /> GENERATE PDF</>
                        }
                    </button>
                </div>
                {error && (
                    <div style={{ marginTop: 12, fontFamily: '"JetBrains Mono"', fontSize: 11, color: '#FFB800' }}>
                        ⚠ {error}
                    </div>
                )}
            </div>

            {/* Previous reports */}
            <div className="card">
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 15, letterSpacing: '0.1em', color: 'var(--text-primary)', marginBottom: 16 }}>
                    PREVIOUS REPORTS
                </div>
                {reportsLoading ? (
                    <div>{[1, 2].map(i => <div key={i} className="skeleton" style={{ height: 16, marginBottom: 10, width: `${50 + i * 20}%` }} />)}</div>
                ) : reports.length === 0 ? (
                    <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: '2rem 0' }}>
                        No reports generated yet.
                    </div>
                ) : reports.map((r, i) => (
                    <div key={r.filename || i} style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        padding: '10px 0', borderBottom: '1px solid rgba(0,212,255,0.04)',
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <FileText size={14} color="var(--text-muted)" />
                            <div>
                                <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 12, color: 'var(--text-primary)' }}>{r.filename || `report_${i + 1}.pdf`}</div>
                                <div style={{ fontFamily: '"JetBrains Mono"', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                                    {r.generated_at?.slice(0, 16).replace('T', ' ') || '—'}
                                    {r.period_from && ` · ${r.period_from} → ${r.period_to}`}
                                </div>
                            </div>
                        </div>
                        <a href={`/api/reports/${r.filename}`} download
                            style={{
                                display: 'flex', alignItems: 'center', gap: 6,
                                fontFamily: '"JetBrains Mono"', fontSize: 11, color: '#00D4FF',
                                textDecoration: 'none', background: 'rgba(0,212,255,0.08)',
                                border: '1px solid rgba(0,212,255,0.2)', borderRadius: 6, padding: '4px 12px',
                            }}>
                            <Download size={12} /> DOWNLOAD
                        </a>
                    </div>
                ))}
            </div>

            <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        input[type="date"]::-webkit-calendar-picker-indicator { filter: invert(0.5); }
        input[type="date"]:focus { border-color: rgba(0,212,255,0.4); }
      `}</style>
        </div>
    )
}
