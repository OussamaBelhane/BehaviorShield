import { createContext, useState, useEffect, useRef } from 'react'
import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar.jsx'
import Topbar from './components/Topbar.jsx'
import AlertBar from './components/AlertBar.jsx'
import BottomBar from './components/BottomBar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Alerts from './pages/Alerts.jsx'
import Quarantine from './pages/Quarantine.jsx'
import Whitelist from './pages/Whitelist.jsx'
import Reports from './pages/Reports.jsx'
import HashScans from './pages/HashScans.jsx'
import SettingsModal from './components/SettingsModal.jsx'
import { usePolling } from './hooks/usePolling.js'

export const ThreatContext = createContext({})

export default function App() {
    const { status, alerts, events, disconnected, refetch } = usePolling()

    const [threatActive, setThreatActive] = useState(false)
    const [latestThreat, setLatestThreat] = useState(null)
    const [topScore, setTopScore] = useState(0)
    const [borderFlash, setBorderFlash] = useState(false)
    const [threatsBlocked, setThreatsBlocked] = useState(0)
    const [settingsOpen, setSettingsOpen] = useState(false)
    const prevTopScore = useRef(0)

    // Derive top score from active alerts + status max_score
    useEffect(() => {
        const active = alerts.filter(a => !a.dismissed)
        const alertMax = active.length > 0 ? Math.max(...active.map(a => a.score)) : 0
        const statusMax = status?.max_score || 0
        const currentTop = Math.max(alertMax, statusMax)
        
        setTopScore(currentTop)

        // Show banner if backend says there's an un-dismissed kill
        if (status?.latest_kill) {
            setLatestThreat(status.latest_kill)
            setThreatActive(true)
            
            if (prevTopScore.current < 60 && currentTop >= 60) {
                setBorderFlash(true)
                setThreatsBlocked(t => t + 1)
                setTimeout(() => setBorderFlash(false), 2200)
            }
        } else {
            setThreatActive(false)
        }
        
        prevTopScore.current = currentTop
    }, [alerts, status])

    const dismissThreat = async () => {
        if (!latestThreat) return
        const id = latestThreat.id
        
        // Hide immediately
        setThreatActive(false)
        
        // Record in localStorage to hide from Alerts page immediately
        try {
            const dismissed = JSON.parse(localStorage.getItem('bs_dismissed_ids') || '[]')
            if (!dismissed.includes(id)) {
                dismissed.push(id)
                localStorage.setItem('bs_dismissed_ids', JSON.stringify(dismissed))
            }
        } catch {}

        // Tell backend to dismiss
        try {
            const { default: axios } = await import('axios')
            await axios.post(`/api/alerts/${id}/dismiss`)
            refetch()
        } catch (err) {
            console.error("Failed to dismiss threat:", err)
        }
    }

    const activeAlerts = alerts.filter(a => !a.dismissed).length

    const ctx = {
        status, alerts, events, disconnected, refetch,
        threatActive, latestThreat, topScore, threatsBlocked,
        activeAlerts,
        dismissThreat,
        settingsOpen,
        setSettingsOpen,
    }

    return (
        <ThreatContext.Provider value={ctx}>
            {/* Full-screen border flash on threat */}
            {borderFlash && (
                <div style={{
                    position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 9999,
                    boxShadow: 'inset 0 0 0 4px rgba(255,45,85,0.9)',
                    animation: 'borderFlash 2.2s ease-out forwards',
                }} />
            )}

            <div style={{
                display: 'flex',
                height: '100vh',
                overflow: 'hidden',
                background: 'var(--bg-deep)',
            }}>
                <Sidebar />

                {/* Main area — offset sidebar */}
                <div style={{
                    marginLeft: 70,
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    overflow: 'hidden',
                }}>
                    <Topbar />
                    <AlertBar />

                    {/* Disconnected banner */}
                    {disconnected && (
                        <div style={{
                            background: 'rgba(255,184,0,0.08)',
                            border: '1px solid rgba(255,184,0,0.25)',
                            borderRadius: 8,
                            margin: '12px 24px 0',
                            padding: '10px 16px',
                            fontFamily: '"JetBrains Mono", monospace',
                            fontSize: 12,
                            color: '#FFB800',
                            display: 'flex', alignItems: 'center', gap: 10,
                        }}>
                            <span>⚠</span>
                            <span>Agent Disconnected — Run BehaviorShield as Administrator</span>
                        </div>
                    )}

                    {/* Page content */}
                    <main style={{
                        flex: 1,
                        overflowY: 'auto',
                        padding: '20px 24px',
                    }}>
                        <Routes>
                            <Route path="/" element={<Dashboard />} />
                            <Route path="/alerts" element={<Alerts />} />
                            <Route path="/quarantine" element={<Quarantine />} />
                            <Route path="/whitelist" element={<Whitelist />} />
                            <Route path="/hash-scans" element={<HashScans />} />
                            <Route path="/reports" element={<Reports />} />
                        </Routes>
                    </main>

                    <BottomBar status={status} eventCount={events.length} />
                </div>
            </div>

            {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
        </ThreatContext.Provider>
    )
}
