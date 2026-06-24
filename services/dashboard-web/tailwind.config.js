/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#090c14",
        surface: "#0f131e",
        surface2: "#151a28",
        line: "#212838",
        line2: "#2c3447",
        brand: {
          DEFAULT: "#38bdf8",
          600: "#0ea5e9",
          700: "#0284c7",
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(56,189,248,0.20), 0 12px 40px -12px rgba(56,189,248,0.30)",
        card: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 12px 28px -18px rgba(0,0,0,0.7)",
        redglow: "0 0 0 1px rgba(244,63,94,0.25), 0 10px 30px -12px rgba(244,63,94,0.35)",
      },
      backgroundImage: {
        "brand-grad": "linear-gradient(135deg, #38bdf8 0%, #6366f1 100%)",
        "dots": "radial-gradient(circle at 1px 1px, rgba(255,255,255,0.045) 1px, transparent 0)",
      },
      keyframes: {
        "fade-in": { "0%": { opacity: "0", transform: "translateY(6px)" }, "100%": { opacity: "1", transform: "none" } },
        "pulse-dot": { "0%,100%": { opacity: "1", transform: "scale(1)" }, "50%": { opacity: "0.35", transform: "scale(0.85)" } },
        "sweep": { "0%": { transform: "translateX(-100%)" }, "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        "fade-in": "fade-in 0.35s ease-out both",
        "pulse-dot": "pulse-dot 1.5s ease-in-out infinite",
        "sweep": "sweep 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
