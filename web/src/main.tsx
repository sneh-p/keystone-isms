import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster, toast } from "sonner";
import "@fontsource-variable/inter";
import "./index.css";
import App from "./App";
import { AuthProvider } from "./lib/auth";
import { ThemeProvider, useTheme } from "./lib/theme";
import { ApiError } from "./lib/api";

const qc = new QueryClient({
  // A page whose data can't be loaded says so, instead of showing its loading placeholder for ever. Sign-in and
  // permission errors are left to the screens (they hide what the user can't use).
  queryCache: new QueryCache({
    onError: (e, q) => {
      if (e instanceof ApiError && [401, 403].includes(e.status)) return;
      toast.error(e.message || "Something went wrong loading this page.", { id: JSON.stringify(q.queryKey) });
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (n, e) => !(e instanceof ApiError && [401, 403, 404].includes(e.status)) && n < 2,
    },
  },
});

function Toasts() {
  const { dark } = useTheme();
  return <Toaster richColors closeButton position="bottom-right" theme={dark ? "dark" : "light"} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <AuthProvider>
            <App />
            <Toasts />
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
);
