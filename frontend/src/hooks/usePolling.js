import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'

// Use relative paths — Vite proxy forwards /api → http://localhost:5000
export function usePolling() {
    const [status, setStatus] = useState(null)
    const [alerts, setAlerts] = useState([])
    const [events, setEvents] = useState([])
    const [disconnected, setDisconnected] = useState(false)

    const fetchAll = useCallback(async () => {
        try {
            const [sRes, aRes, eRes] = await Promise.all([
                axios.get('/api/status'),
                axios.get('/api/alerts'),
                axios.get('/api/events?per_page=50'),
            ])
            setStatus(sRes.data)
            setAlerts((aRes.data.alerts || []).sort((a, b) => b.score - a.score))
            setEvents(eRes.data.events || [])
            setDisconnected(false)
        } catch {
            setDisconnected(true)
        }
    }, [])

    useEffect(() => {
        fetchAll()
        const id = setInterval(fetchAll, 2000)
        return () => clearInterval(id)
    }, [fetchAll])

    return { status, alerts, events, disconnected, refetch: fetchAll }
}
