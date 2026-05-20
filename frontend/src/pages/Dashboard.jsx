import { useContext } from 'react'
import { Cpu, FolderOpen, Skull, Zap } from 'lucide-react'
import { ThreatContext } from '../App.jsx'
import StatCard from '../components/StatCard.jsx'
import ShieldCore from '../components/ShieldCore.jsx'
import LiveEventFeed from '../components/LiveEventFeed.jsx'
import ThreatGauge from '../components/ThreatGauge.jsx'
import RulesPanel from '../components/RulesPanel.jsx'

function getTriggeredRules(alerts) {
    const active = alerts.filter(a => !a.dismissed)
    if (!active.length) return []
    return active[0].triggered_rules || []
}

export default function Dashboard() {
    const { status, alerts, events, topScore } = useContext(ThreatContext)

    const activeCount = alerts.filter(a => !a.dismissed).length
    const triggeredRules = getTriggeredRules(alerts)

    return (
        <div style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            gap: 18, 
            height: 'calc(100vh - 160px)', // Account for Topbar, AlertBar, BottomBar and padding
            minHeight: 600
        }}>

            {/* ── Stat cards ── */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, flexShrink: 0 }}>
                <StatCard icon={Cpu} label="PROCESSES MONITORED" value={status?.processes_count ?? '—'} color="#00D4FF" />
                <StatCard icon={FolderOpen} label="FILES WATCHED" value={status?.total_events ?? 0} color="#E8EDF5" />
                <StatCard icon={Skull} label="THREATS BLOCKED" value={status?.killed_processes ?? 0} color="#FF2D55" />
                <StatCard icon={Zap} label="ACTIVE ALERTS" value={activeCount} color="#E8EDF5" />
            </div>

            {/* ── Main 3-col grid ── */}
            <div style={{ 
                display: 'grid', 
                gridTemplateColumns: '220px 1fr 240px', 
                gap: 14, 
                alignItems: 'stretch',
                flex: 1,
                minHeight: 0 
            }}>
                <ShieldCore status={status} />
                <div style={{ height: '100%', overflow: 'hidden' }}>
                    <LiveEventFeed />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto', paddingRight: 4 }}>
                    <ThreatGauge score={topScore} />
                    <RulesPanel
                        triggeredRules={triggeredRules}
                        watchingRules={topScore > 0 && topScore < 60 ? ['MASS_RENAME', 'CROSS_DIR_ENCRYPTION', 'READ_WRITE_STORM'] : []}
                    />
                </div>
            </div>
        </div>
    )
}
