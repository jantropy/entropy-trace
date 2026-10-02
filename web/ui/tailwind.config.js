/** @type {import('tailwindcss').Config} */
// "Bone and tomato": a near-black page, cream text, one hot accent. Tomato is
// reserved for a weak result, amber for "could not finish", mint for a
// confirmed good one; an unknown is never drawn in tomato.
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#151412',
        surface: '#1c1b17',
        line: '#2a2723',
        'line-strong': '#3b3731',
        bone: '#ede6dc',
        dim: '#a39f97',
        tomato: '#ff6a45',
        'tomato-soft': '#ff8761',
        'tomato-deep': '#291a15',
        amber: '#ead16e',
        mint: '#96d6ba',
      },
      fontFamily: {
        sans: ['"Bricolage Grotesque Variable"', '-apple-system', 'Segoe UI', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['"Space Mono"', 'SF Mono', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
