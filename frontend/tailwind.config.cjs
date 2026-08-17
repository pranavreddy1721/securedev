/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Deliberate dark-navy/slate base + a single controlled accent (teal),
        // per the confirmed design direction. Severity colors are kept
        // separate and used consistently everywhere they appear.
        surface: {
          DEFAULT: '#ffffff',
          dark: '#0b1220',
        },
        panel: {
          DEFAULT: '#f8fafc',
          dark: '#111a2e',
        },
        border: {
          DEFAULT: '#e2e8f0',
          dark: '#22314f',
        },
        ink: {
          DEFAULT: '#0f172a',
          dark: '#e6ebf5',
        },
        muted: {
          DEFAULT: '#64748b',
          dark: '#8b99b8',
        },
        accent: {
          50: '#effcf9',
          100: '#c7f5ea',
          300: '#5fddc4',
          500: '#14b89c',
          600: '#0e9683',
          700: '#0b7a6b',
        },
        severity: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#d97706',
          low: '#65a30d',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
    },
  },
  plugins: [],
};
