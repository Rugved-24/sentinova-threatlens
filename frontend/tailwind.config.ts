import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "rgb(var(--ink-950) / <alpha-value>)",
          900: "rgb(var(--ink-900) / <alpha-value>)",
          850: "rgb(var(--ink-850) / <alpha-value>)",
          800: "rgb(var(--ink-800) / <alpha-value>)",
          700: "rgb(var(--ink-700) / <alpha-value>)",
          600: "rgb(var(--ink-600) / <alpha-value>)",
        },
        mint: "#34d399",
        amber: {
          DEFAULT: "#fbbf24",
          200: "#fde68a",
          300: "#fcd34d",
          400: "#fbbf24",
          500: "#f59e0b",
        },
        rose: {
          DEFAULT: "#fb7185",
          200: "#fecdd3",
          300: "#fda4af",
          400: "#fb7185",
          500: "#f43f5e",
        },
        violet: {
          DEFAULT: "#a78bfa",
          200: "#ddd6fe",
          300: "#c4b5fd",
          400: "#a78bfa",
          500: "#8b5cf6",
        },
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "Consolas", "monospace"],
      },
      opacity: {
        8: "0.08",
        12: "0.12",
        15: "0.15",
        35: "0.35",
        98: "0.98",
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34,211,238,0.16), 0 18px 50px -20px rgba(34,211,238,0.25)",
        panel: "0 20px 60px -32px rgba(0,0,0,0.9)",
      },
      backgroundImage: {
        grid: "linear-gradient(rgba(34,211,238,0.055) 1px, transparent 1px), linear-gradient(90deg, rgba(34,211,238,0.055) 1px, transparent 1px)",
        "radial-cyan": "radial-gradient(circle at center, rgba(34,211,238,0.16), transparent 65%)",
      },
      animation: {
        "pulse-slow": "pulse 3.2s cubic-bezier(0.4,0,0.6,1) infinite",
        float: "float 7s ease-in-out infinite",
        "fade-up": "fadeUp 0.45s ease-out both",
        scan: "scan 7s linear infinite",
      },
      keyframes: {
        float: {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-10px)" },
        },
        fadeUp: {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
