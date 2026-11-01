import { CheckCircle2, Info, TriangleAlert, X } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { cn } from "../lib/utils";

type ToastKind = "success" | "error" | "info";

interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
}

interface ToastContextValue {
  push: (kind: ToastKind, title: string, message?: string) => void;
  success: (title: string, message?: string) => void;
  error: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, title: string, message?: string) => {
      const id = Date.now() + Math.random();
      setToasts((current) => [...current.slice(-3), { id, kind, title, message }]);
      window.setTimeout(() => remove(id), kind === "error" ? 7000 : 4500);
    },
    [remove],
  );

  const value = useMemo<ToastContextValue>(
    () => ({
      push,
      success: (title, message) => push("success", title, message),
      error: (title, message) => push("error", title, message),
      info: (title, message) => push("info", title, message),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-5 right-5 z-[80] flex w-[min(380px,calc(100vw-2.5rem))] flex-col gap-2">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={cn(
              "pointer-events-auto flex animate-fade-up items-start gap-3 rounded-2xl border bg-ink-850/95 p-4 shadow-panel backdrop-blur-xl",
              toast.kind === "success" && "border-mint/30",
              toast.kind === "error" && "border-rose-400/35",
              toast.kind === "info" && "border-cyan-400/25",
            )}
          >
            {toast.kind === "success" ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-mint" />
            ) : toast.kind === "error" ? (
              <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-300" />
            ) : (
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-slate-100">{toast.title}</p>
              {toast.message && <p className="mt-1 text-xs leading-relaxed text-slate-400">{toast.message}</p>}
            </div>
            <button
              type="button"
              onClick={() => remove(toast.id)}
              className="text-slate-500 transition hover:text-slate-200"
              aria-label="Dismiss notification"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used inside ToastProvider");
  return value;
}
