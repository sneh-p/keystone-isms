/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: { sans: ["'Inter Variable'", "ui-sans-serif", "system-ui", "sans-serif"] },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: { DEFAULT: "hsl(var(--primary))", foreground: "hsl(var(--primary-foreground))" },
        secondary: { DEFAULT: "hsl(var(--secondary))", foreground: "hsl(var(--secondary-foreground))" },
        muted: { DEFAULT: "hsl(var(--muted))", foreground: "hsl(var(--muted-foreground))" },
        accent: { DEFAULT: "hsl(var(--accent))", foreground: "hsl(var(--accent-foreground))" },
        card: { DEFAULT: "hsl(var(--card))", foreground: "hsl(var(--card-foreground))" },
        popover: { DEFAULT: "hsl(var(--popover))", foreground: "hsl(var(--popover-foreground))" },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar))",
          foreground: "hsl(var(--sidebar-foreground))",
          active: "hsl(var(--sidebar-active))",
          "active-foreground": "hsl(var(--sidebar-active-foreground))",
          muted: "hsl(var(--sidebar-muted))",
          hover: "hsl(var(--sidebar-hover))",
          border: "hsl(var(--sidebar-border))",
          indicator: "hsl(var(--sidebar-indicator))",
        },
        // Status fills (badges, bars, heat map) stay fixed; *-fg are the text shades that reach WCAG AA 4.5:1 on
        // cards in each theme, so pages never hard-code a hex value for coloured text.
        good: { DEFAULT: "#0ca30c", fg: "hsl(var(--good-fg))" },
        warning: { DEFAULT: "#fab219", fg: "hsl(var(--warning-fg))" },
        serious: { DEFAULT: "#ec835a", fg: "hsl(var(--serious-fg))" },
        critical: { DEFAULT: "#d03b3b", fg: "hsl(var(--critical-fg))" },
        brand: { DEFAULT: "hsl(var(--brand))", foreground: "hsl(var(--brand-foreground))" },
      },
      borderRadius: { xl: "0.875rem", lg: "0.75rem", md: "0.5rem", sm: "0.375rem" },
      boxShadow: {
        card: "0 1px 2px 0 rgb(15 23 42 / 0.05), 0 1px 1px -1px rgb(15 23 42 / 0.04)",
        raised: "0 4px 12px -2px rgb(15 23 42 / 0.08), 0 2px 4px -2px rgb(15 23 42 / 0.05)",
        pop: "0 16px 40px -8px rgb(15 23 42 / 0.22), 0 4px 10px -4px rgb(15 23 42 / 0.10)",
      },
      keyframes: { "fade-in": { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "none" } } },
      animation: { "fade-in": "fade-in .2s ease-out" },
    },
  },
  plugins: [],
};
