import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

type Theme = "light" | "dark" | "system";
const Ctx = createContext<{ theme: Theme; setTheme: (t: Theme) => void; dark: boolean }>({ theme: "system", setTheme: () => {}, dark: false });

function read(): Theme {
  try {
    return (localStorage.getItem("ks-theme") as Theme) || "system";
  } catch {
    return "system";
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(read);
  const [systemDark, setSystemDark] = useState(() => window.matchMedia("(prefers-color-scheme: dark)").matches);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const fn = () => setSystemDark(mq.matches);
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, []);
  const dark = theme === "dark" || (theme === "system" && systemDark);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);
  const setTheme = (t: Theme) => {
    setThemeState(t);
    try {
      localStorage.setItem("ks-theme", t);
    } catch {
      /* storage unavailable */
    }
  };
  return <Ctx.Provider value={{ theme, setTheme, dark }}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);
