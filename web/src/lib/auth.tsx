import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, ApiError, setCsrf } from "./api";

export type Me = {
  id: number;
  username: string;
  display_name: string;
  email: string | null;
  role: string;
  role_label: string;
  permissions: string[];
  must_change_password: boolean;
  csrf_token: string;
};

type AuthState = {
  me: Me | null;
  loading: boolean;
  needsBootstrap: boolean;
  can: (perm: string) => boolean;
  login: (username: string, password: string) => Promise<void>;
  bootstrap: (b: { username: string; display_name: string; password: string; email?: string }) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsBootstrap, setNeedsBootstrap] = useState(false);
  const qc = useQueryClient();

  const accept = (m: Me | null) => {
    setCsrf(m?.csrf_token ?? null);
    setMe(m);
  };

  const refresh = useCallback(async () => {
    try {
      accept(await api<Me>("/auth/me"));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        accept(null);
        const st = await api<{ needs_bootstrap: boolean }>("/auth/status");
        setNeedsBootstrap(st.needs_bootstrap);
      } else throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const value: AuthState = {
    me,
    loading,
    needsBootstrap,
    can: (p) => !!me?.permissions.includes(p),
    login: async (username, password) => {
      accept(await api<Me>("/auth/login", { body: { username, password } }));
      qc.clear();
    },
    bootstrap: async (b) => {
      accept(await api<Me>("/auth/bootstrap", { body: b }));
      setNeedsBootstrap(false);
    },
    logout: async () => {
      try {
        await api("/auth/logout", { method: "POST" });
      } finally {
        accept(null);
        qc.clear();
      }
    },
    refresh,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
