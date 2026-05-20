import {
    FileEdit, Binary, FileStack, KeyRound, Trash2, Zap, Flower
} from 'lucide-react'

const RULES = [
    { id: 'MASS_RENAME', name: 'Mass File Rename', points: 10, Icon: FileEdit },
    { id: 'RANSOM_EXTENSION', name: 'Ransom Extension', points: 20, Icon: FileStack },
    { id: 'CROSS_DIR_ENCRYPTION', name: 'Cross Dir Encryption', points: 20, Icon: Binary },
    { id: 'UNSIGNED_APPDATA', name: 'Unsigned AppData', points: 10, Icon: KeyRound },
    { id: 'READ_WRITE_STORM', name: 'Read/Write Storm', points: 15, Icon: Zap },
    { id: 'KNOWN_RANSOM_EXT', name: 'Known Ransom Ext', points: 25, Icon: Trash2 },
    { id: 'SHADOW_COPY_DELETE', name: 'Shadow Copy Delete', points: 60, Icon: Flower },
]

export default function RulesPanel({ triggeredRules = [], watchingRules = [] }) {
    return (
        <div className="card">
            <div style={{
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
                fontSize: 13, letterSpacing: '0.12em', color: 'var(--text-muted)',
                marginBottom: 12,
            }}>
                DETECTION RULES
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {RULES.map(({ id, name, points, Icon }) => {
                    const triggered = triggeredRules.includes(id)
                    const watching = !triggered && watchingRules.includes(id)

                    const borderColor = triggered ? '#FF2D55' : watching ? '#FFB800' : 'rgba(255,255,255,0.04)'
                    const bg = triggered ? 'rgba(255,45,85,0.06)' : watching ? 'rgba(255,184,0,0.05)' : 'transparent'
                    const ptColor = triggered ? '#FF2D55' : watching ? '#FFB800' : 'var(--text-muted)'
                    const nameColor = triggered ? '#FF2D55' : watching ? '#FFB800' : 'var(--text-secondary)'
                    const iconColor = triggered ? '#FF2D55' : watching ? '#FFB800' : 'var(--text-muted)'

                    return (
                        <div key={id} style={{
                            display: 'flex', alignItems: 'center', gap: 10,
                            padding: '7px 10px', borderRadius: 6,
                            borderLeft: `3px solid ${borderColor}`,
                            background: bg, transition: 'all 0.4s ease',
                        }}>
                            <Icon size={13} color={iconColor} strokeWidth={1.8} style={{ flexShrink: 0, transition: 'color 0.4s' }} />
                            <span style={{
                                fontFamily: '"JetBrains Mono", monospace',
                                fontSize: 11, color: nameColor, flex: 1,
                                transition: 'color 0.4s',
                            }}>{name}</span>
                            <span style={{
                                fontFamily: '"JetBrains Mono", monospace',
                                fontSize: 11, fontWeight: 700, color: ptColor,
                                textShadow: triggered ? '0 0 8px rgba(255,45,85,0.6)' : 'none',
                                transition: 'color 0.4s, text-shadow 0.4s',
                            }}>+{points}</span>
                            {triggered && (
                                <span style={{
                                    width: 6, height: 6, borderRadius: '50%',
                                    background: '#FF2D55', boxShadow: '0 0 6px #FF2D55',
                                    animation: 'pulseDot 1s ease-in-out infinite',
                                    flexShrink: 0,
                                }} />
                            )}
                        </div>
                    )
                })}
            </div>
        </div>
    )
}
