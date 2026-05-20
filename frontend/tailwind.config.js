/** @type {import('tailwindcss').Config} */
export default {
    content: ['./index.html', './src/**/*.{js,jsx}'],
    theme: {
        extend: {
            colors: {
                bg: {
                    deep: '#06080F',
                    surface: '#0C0F1A',
                    card: '#111827',
                },
                cyan: {
                    DEFAULT: '#00D4FF',
                    dim: 'rgba(0,212,255,0.08)',
                    glow: 'rgba(0,212,255,0.25)',
                },
                amber: {
                    DEFAULT: '#FFB800',
                    dim: 'rgba(255,184,0,0.10)',
                },
                danger: {
                    DEFAULT: '#FF2D55',
                    dim: 'rgba(255,45,85,0.10)',
                    glow: 'rgba(255,45,85,0.35)',
                },
                success: {
                    DEFAULT: '#00FF94',
                    dim: 'rgba(0,255,148,0.10)',
                },
                text: {
                    primary: '#E8EDF5',
                    secondary: '#8899B0',
                    muted: '#3D5060',
                },
            },
            fontFamily: {
                rajdhani: ['Rajdhani', 'sans-serif'],
                mono: ['"JetBrains Mono"', 'monospace'],
                syne: ['Syne', 'sans-serif'],
            },
            animation: {
                'ring-1': 'ring-pulse 3s ease-out infinite',
                'ring-2': 'ring-pulse 3s ease-out infinite 1s',
                'ring-3': 'ring-pulse 3s ease-out infinite 2s',
                'float': 'float 4s ease-in-out infinite',
                'fade-up': 'fadeUp 0.35s ease-out',
                'slide-down': 'slideDown 0.3s ease-out',
                'border-flash': 'borderFlash 2s ease-out forwards',
                'blink': 'blink 1.2s step-start infinite',
                'pulse-dot': 'pulseDot 2s ease-in-out infinite',
            },
            keyframes: {
                'ring-pulse': {
                    '0%': { transform: 'scale(1)', opacity: '0.6' },
                    '70%': { transform: 'scale(1.35)', opacity: '0' },
                    '100%': { transform: 'scale(1.35)', opacity: '0' },
                },
                float: {
                    '0%,100%': { transform: 'translateY(0px)' },
                    '50%': { transform: 'translateY(-6px)' },
                },
                fadeUp: {
                    '0%': { opacity: '0', transform: 'translateY(10px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                slideDown: {
                    '0%': { maxHeight: '0', opacity: '0' },
                    '100%': { maxHeight: '80px', opacity: '1' },
                },
                borderFlash: {
                    '0%,20%': { boxShadow: 'inset 0 0 0 3px rgba(255,45,85,0.8)' },
                    '100%': { boxShadow: 'inset 0 0 0 3px rgba(255,45,85,0)' },
                },
                blink: {
                    '0%,49%': { opacity: '1' },
                    '50%,100%': { opacity: '0' },
                },
                pulseDot: {
                    '0%,100%': { opacity: '1', transform: 'scale(1)' },
                    '50%': { opacity: '0.4', transform: 'scale(0.8)' },
                },
            },
        },
    },
    plugins: [],
}
