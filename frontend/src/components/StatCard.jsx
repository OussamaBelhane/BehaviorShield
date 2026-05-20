export default function StatCard({ label, value, color = '#E8EDF5', icon: Icon }) {
    return (
        <div className="card" style={{ position: 'relative', overflow: 'hidden', cursor: 'default' }}>
            {/* Ghost icon — lucide SVG at very low opacity */}
            {Icon && (
                <div style={{
                    position: 'absolute', top: 14, right: 14,
                    opacity: 0.07, pointerEvents: 'none',
                }}>
                    <Icon size={28} color="#00D4FF" strokeWidth={1.5} />
                </div>
            )}
            {/* Value */}
            <div style={{
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
                fontSize: 38, lineHeight: 1, color,
                letterSpacing: '-0.01em',
                textShadow: `0 0 20px ${color}40`,
                fontVariantNumeric: 'tabular-nums',
            }}>
                {value ?? '—'}
            </div>
            {/* Label */}
            <div style={{
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 11, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 6,
            }}>
                {label}
            </div>
        </div>
    )
}
