/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#1c1814",
        paper: "#f3eee4",
        panel: "#fffdf8",
        rule: "#d8cfc0",
        forest: "#1c5c45",
        carmine: "#8b1e3f",
        brass: "#9a6b2f",
        navy: "#243044",
      },
      fontFamily: {
        serif: ["var(--font-serif)", "Georgia", "serif"],
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
