const W = 200
const H = 130
const CX = 100
const CY = 105
const R = 82

function polarToXY(angleDeg, r) {
    const rad = ((angleDeg - 180) * Math.PI) / 180
    return {
        x: CX + r * Math.cos(rad),
        y: CY + r * Math.sin(rad),
    }
}

function arcPath(startDeg, endDeg, r) {
    const s = polarToXY(startDeg, r)
    const e = polarToXY(endDeg, r)
    const large = endDeg - startDeg > 180 ? 1 : 0
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`
}

// 0–180 degrees spread (left to right)
const START = 0
const END = 180

function scoreToAngle(score) {
    return START + (Math.min(score, 100) / 100) * (END - START)
}

const ZONES = [
    { from: 0, to: 40, color: '#00FF94' },
    { from: 40, to: 70, color: '#FFB800' },
    { from: 70, to: 100, color: '#FF2D55' },
]

export default function ThreatGauge({ score = 0 }) {
    const activeDeg = scoreToAngle(score)
    const gaugeColor = score >= 70 ? '#FF2D55' : score >= 40 ? '#FFB800' : '#00FF94'

    return (
        <div className="card" style={{ textAlign: 'center', overflow: 'visible', paddingBottom: 12 }}>
            <div style={{
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
                fontSize: 13, letterSpacing: '0.12em', color: 'var(--text-muted)',
                marginBottom: 8,
            }}>
                THREAT GAUGE
            </div>

            <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', maxWidth: 240, display: 'block', margin: '0 auto' }}>
                <defs>
                    <filter id="gaugeglow">
                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                        <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                    </filter>
                </defs>

                {/* Background track */}
                <path d={arcPath(START, END, R)} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" strokeLinecap="round" />

                {/* Zone arcs */}
                {ZONES.map((z, i) => {
                    const s = START + (z.from / 100) * (END - START)
                    const e = START + (z.to / 100) * (END - START)
                    return (
                        <path
                            key={i}
                            d={arcPath(s, e, R)}
                            fill="none"
                            stroke={z.color}
                            strokeWidth="6"
                            opacity="0.18"
                            strokeLinecap="butt"
                        />
                    )
                })}

                {/* Active arc */}
                {activeDeg > START && (
                    <path
                        d={arcPath(START, activeDeg, R)}
                        fill="none"
                        stroke={gaugeColor}
                        strokeWidth="7"
                        strokeLinecap="round"
                        filter="url(#gaugeglow)"
                        style={{ transition: 'all 0.6s ease' }}
                    />
                )}

                {/* Tick marks */}
                {[0, 25, 50, 75, 100].map(v => {
                    const deg = scoreToAngle(v)
                    const inner = polarToXY(deg, R - 12)
                    const outer = polarToXY(deg, R + 4)
                    return (
                        <line key={v} x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
                            stroke="rgba(255,255,255,0.15)" strokeWidth="1.5" />
                    )
                })}

                {/* Score label */}
                <text x="50%" y="88" textAnchor="middle"
                    style={{
                        fontFamily: 'Rajdhani, sans-serif',
                        fontSize: 36, fontWeight: 700, fill: gaugeColor,
                        filter: `drop-shadow(0 0 8px ${gaugeColor}80)`,
                        transition: 'fill 0.5s ease',
                    }}>
                    {score}
                </text>

                {/* MIN/MAX labels */}
                <text x="14" y={H - 5} textAnchor="middle" style={{ fontFamily: '"JetBrains Mono"', fontSize: 9, fill: 'var(--text-muted)' }}>0</text>
                <text x={W - 14} y={H - 5} textAnchor="middle" style={{ fontFamily: '"JetBrains Mono"', fontSize: 9, fill: 'var(--text-muted)' }}>100</text>
            </svg>

            {/* Zone legend */}
            <div style={{ display: 'flex', justifyContent: 'center', gap: 14, marginTop: 4 }}>
                {[['#00FF94', 'SAFE'], ['#FFB800', 'WARN'], ['#FF2D55', 'CRIT']].map(([c, l]) => (
                    <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: c }} />
                        <span style={{ fontFamily: '"JetBrains Mono"', fontSize: 8, color: 'var(--text-muted)', letterSpacing: '0.04em' }}>{l}</span>
                    </div>
                ))}
            </div>
        </div>
    )
}
