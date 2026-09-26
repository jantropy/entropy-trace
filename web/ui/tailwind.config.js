/** @type {import('tailwindcss').Config} */
// Same palette as entropytrace/emit/report.py -- one visual language
// across the HTML report and this UI.
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#17140F',
        'bg-raised': '#201B13',
        'bg-card': '#221D15',
        border: '#3A3123',
        text: '#EFE8D8',
        'text-dim': '#A89E88',
        accent: '#F7931A',
        fail: '#E24B4A',
      },
      fontFamily: {
        mono: ['SF Mono', 'Menlo', 'Consolas', 'Liberation Mono', 'monospace'],
        sans: ['-apple-system', 'Segoe UI', 'Helvetica Neue', 'Arial', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
