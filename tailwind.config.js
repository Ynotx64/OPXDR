/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "0.95rem" }],
        "3xs": ["0.625rem", { lineHeight: "0.8rem" }],
      },
      colors: {
        bg: {
          0: "#070b16",
          1: "#0d1222",
          2: "#141a2d",
          3: "#1c2438",
        },
        ink: {
          0: "#f8fafc",
          1: "#d7deea",
          2: "#9aa5b8",
          3: "#68758b",
          4: "#455066",
        },
        border: {
          DEFAULT: "#20283d",
          strong: "#303a56",
        },
        brand: {
          DEFAULT: "#7c5cff",
          accent: "#9b8cff",
        },
        sev: {
          critical: "#ff4d5f",
          high: "#ff8a2a",
          medium: "#f6c343",
          low: "#45d483",
          info: "#55b8ff",
        },
        ok: "#20d071",
        bad: "#ff5c75",
        info: "#55b8ff",
        live: "#22c55e",
      },
      boxShadow: {
        panel: "0 10px 30px rgba(0, 0, 0, 0.18)",
        glow: "0 0 22px rgba(124, 92, 255, 0.38)",
      },
    },
  },
  plugins: [],
};
