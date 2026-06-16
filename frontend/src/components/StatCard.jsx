export default function StatCard({ label, value, color = '#00D4FF', icon: Icon, sub }) {
  const glowRgb = color === '#FF2D55' ? '255,45,85'
                : color === '#FFB800' ? '255,184,0'
                : color === '#00FF94' ? '0,255,148'
                : '0,212,255'

  return (
    <div
      className="stat-card"
      style={{
        '--accent': `rgba(${glowRgb},0.32)`,
        '--accent-glow': `rgba(${glowRgb},0.06)`,
      }}
    >
      {/* Left edge accent bar */}
      <div style={{
        position: 'absolute', top: 12, bottom: 12, left: 0,
        width: 3, borderRadius: '0 3px 3px 0',
        background: color,
        boxShadow: `0 0 10px rgba(${glowRgb},0.6)`,
      }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginLeft: 8 }}>
        <div>
          {/* Label */}
          <div style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 10, color: 'var(--text-muted)',
            textTransform: 'uppercase', letterSpacing: '0.1em',
            marginBottom: 8,
          }}>
            {label}
          </div>

          {/* Value */}
          <div style={{
            fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
            fontSize: 42, lineHeight: 1, color,
            letterSpacing: '-0.01em',
            textShadow: `0 0 24px rgba(${glowRgb},0.35)`,
            fontVariantNumeric: 'tabular-nums',
          }}>
            {value ?? '—'}
          </div>

          {/* Sub label */}
          {sub && (
            <div style={{
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: 9, color: 'var(--text-muted)',
              marginTop: 4, letterSpacing: '0.06em',
            }}>{sub}</div>
          )}
        </div>

        {/* Ghost icon */}
        {Icon && (
          <div style={{
            marginTop: 2,
            padding: 8,
            background: `rgba(${glowRgb},0.07)`,
            borderRadius: 8,
            border: `1px solid rgba(${glowRgb},0.15)`,
          }}>
            <Icon size={20} color={color} strokeWidth={1.5} />
          </div>
        )}
      </div>
    </div>
  )
}
