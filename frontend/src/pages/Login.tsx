import {
  ArrowRight,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  Loader2,
  LockKeyhole,
  Radar,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { ApiError } from "../lib/api";
import { ROLE_LABEL } from "../lib/utils";

const DEMO_ACCOUNTS = [
  { role: "admin", email: "admin@threatlens.io", name: "Aarav Mehta" },
  { role: "analyst", email: "analyst@threatlens.io", name: "Priya Nair" },
  { role: "responder", email: "responder@threatlens.io", name: "Daniel Okafor" },
  { role: "hunter", email: "hunter@threatlens.io", name: "Mei Lin Tan" },
  { role: "engineer", email: "engineer@threatlens.io", name: "Elena Fischer" },
  { role: "executive", email: "exec@threatlens.io", name: "Rachel Adeyemi" },
] as const;

const DEMO_PASSWORD = "ThreatLens#2026!";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [email, setEmail] = useState("admin@threatlens.io");
  const [password, setPassword] = useState(DEMO_PASSWORD);
  const [otp, setOtp] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showOtp, setShowOtp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const user = await login(email.trim(), password, otp || undefined);
      toast.success(`Welcome, ${user.name.split(" ")[0]}`, `${ROLE_LABEL[user.role]} workspace ready.`);
      navigate("/", { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.message.toLowerCase().includes("multi-factor")) {
          setShowOtp(true);
          setError("Enter the six-digit code from your authenticator.");
        } else {
          setError(err.message);
        }
      } else {
        setError("Unable to reach the intelligence service.");
      }
    } finally {
      setLoading(false);
    }
  };

  const chooseAccount = (account: (typeof DEMO_ACCOUNTS)[number]) => {
    setEmail(account.email);
    setPassword(DEMO_PASSWORD);
    setError("");
    setShowOtp(false);
    setOtp("");
  };

  return (
    <div className="relative flex min-h-screen overflow-hidden bg-ink-950">
      <div className="pointer-events-none absolute inset-0 bg-grid bg-[size:48px_48px] opacity-35 [mask-image:radial-gradient(ellipse_at_30%_40%,black,transparent_78%)]" />
      <div className="pointer-events-none absolute -left-40 top-1/4 h-[560px] w-[560px] rounded-full bg-cyan-400/[0.07] blur-3xl" />
      <div className="pointer-events-none absolute -right-24 bottom-0 h-[420px] w-[420px] rounded-full bg-violet/[0.07] blur-3xl" />

      <section className="relative hidden w-[55%] flex-col justify-between border-r border-ink-600/40 p-12 lg:flex xl:p-16">
        <div className="flex items-center gap-3">
          <div className="relative flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
            <Fingerprint className="h-5 w-5 text-cyan-300" />
            <span className="absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full bg-mint shadow-[0_0_10px_#34d399]" />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-[0.2em] text-white">THREATLENS</p>
            <p className="text-[9px] uppercase tracking-[0.3em] text-slate-500">Sentinova intelligence</p>
          </div>
        </div>

        <div className="relative max-w-xl">
          <div className="pointer-events-none absolute -right-24 -top-24 h-[360px] w-[360px]">
            <div className="absolute inset-0 rounded-full border border-cyan-400/10" />
            <div className="absolute inset-8 rounded-full border border-cyan-400/10" />
            <div className="absolute inset-16 rounded-full border border-cyan-400/10" />
            <div className="absolute inset-[6.5rem] rounded-full border border-cyan-400/20" />
            <div className="absolute inset-[6.5rem] animate-spin rounded-full border border-transparent border-t-cyan-300/60 [animation-duration:8s]" />
            <div className="absolute left-1/2 top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-cyan-300 shadow-[0_0_16px_#22d3ee]" />
            <div className="absolute left-[28%] top-[34%] h-1.5 w-1.5 rounded-full bg-rose-400 shadow-[0_0_10px_#fb7185]" />
            <div className="absolute bottom-[26%] right-[30%] h-1.5 w-1.5 rounded-full bg-amber shadow-[0_0_10px_#fbbf24]" />
          </div>

          <p className="label mb-4 text-cyan-400/80">Operational intelligence, unified</p>
          <h1 className="text-5xl font-semibold leading-[1.05] tracking-tight text-white xl:text-6xl">
            See the threat.
            <br />
            <span className="text-gradient">Shape the response.</span>
          </h1>
          <p className="mt-6 max-w-lg text-sm leading-7 text-slate-400">
            Aggregate, score and correlate indicators across public and private sources. Move from a noisy
            feed to an explainable, auditable investigation — in one console.
          </p>

          <div className="mt-8 flex flex-wrap gap-2">
            {[
              { icon: Radar, label: "Live correlation" },
              { icon: ShieldCheck, label: "TLP-aware RBAC" },
              { icon: Zap, label: "Transparent scoring" },
              { icon: Sparkles, label: "ATT&CK overlay" },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <span key={item.label} className="chip border-ink-600/60 bg-ink-850/60 text-slate-300">
                  <Icon className="h-3 w-3 text-cyan-300" /> {item.label}
                </span>
              );
            })}
          </div>

          <div className="mt-10 grid max-w-lg grid-cols-3 gap-3">
            {[
              ["706", "ATT&CK techniques"],
              ["13", "Feed connectors"],
              ["0-100", "Severity model"],
            ].map(([value, label]) => (
              <div key={label} className="rounded-2xl border border-ink-600/50 bg-ink-850/40 px-4 py-3">
                <p className="font-mono text-xl font-semibold text-cyan-200">{value}</p>
                <p className="mt-1 text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-between text-[10px] text-slate-600">
          <span>Synthetic demo dataset · reserved documentation ranges</span>
          <span className="font-mono">v1.0.0</span>
        </div>
      </section>

      <section className="relative flex w-full flex-col justify-center px-5 py-10 sm:px-10 lg:w-[45%] lg:px-12 xl:px-16">
        <div className="mx-auto w-full max-w-md">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/25 bg-cyan-400/10">
              <Fingerprint className="h-5 w-5 text-cyan-300" />
            </div>
            <div>
              <p className="text-sm font-semibold tracking-[0.16em] text-white">THREATLENS</p>
              <p className="text-[9px] uppercase tracking-[0.24em] text-slate-500">Sentinova intelligence</p>
            </div>
          </div>

          <div className="panel bg-ink-850/75 p-6 sm:p-8">
            <div className="mb-6">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/5 px-3 py-1 text-[10px] font-medium uppercase tracking-[0.16em] text-cyan-300">
                <LockKeyhole className="h-3 w-3" /> Secure access
              </div>
              <h2 className="text-2xl font-semibold tracking-tight text-white">Enter the operations console</h2>
              <p className="mt-2 text-sm text-slate-500">Authenticate to view intelligence cleared for your role.</p>
            </div>

            <form onSubmit={submit} className="space-y-4">
              <div>
                <label htmlFor="email" className="label mb-1.5 block">
                  Work email
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className="input"
                  autoComplete="username"
                  placeholder="analyst@threatlens.io"
                />
              </div>

              <div>
                <label htmlFor="password" className="label mb-1.5 block">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    className="input pr-11"
                    autoComplete="current-password"
                    placeholder="••••••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((value) => !value)}
                    className="absolute right-3 top-2.5 text-slate-500 transition hover:text-slate-200"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {showOtp && (
                <div>
                  <label htmlFor="otp" className="label mb-1.5 block">
                    Authenticator code
                  </label>
                  <input
                    id="otp"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    value={otp}
                    onChange={(event) => setOtp(event.target.value.replace(/\D/g, ""))}
                    className="input font-mono tracking-[0.4em]"
                    placeholder="000000"
                    autoFocus
                  />
                </div>
              )}

              {error && (
                <div className="rounded-xl border border-rose-400/25 bg-rose-500/8 px-3.5 py-2.5 text-xs text-rose-200">
                  {error}
                </div>
              )}

              <button type="submit" disabled={loading} className="btn-primary w-full py-2.5">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                {loading ? "Authenticating…" : "Authenticate"}
                {!loading && <ArrowRight className="h-4 w-4" />}
              </button>

              <button
                type="button"
                onClick={() => setShowOtp((value) => !value)}
                className="w-full text-center text-[11px] text-slate-500 transition hover:text-slate-300"
              >
                {showOtp ? "Hide authenticator code" : "Use an authenticator code"}
              </button>
            </form>
          </div>

          <div className="mt-5 rounded-2xl border border-ink-600/50 bg-ink-900/50 p-4">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Demo access</p>
              <span className="chip border-amber-400/20 bg-amber-400/5 text-[9px] text-amber-300">Synthetic environment</span>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              {DEMO_ACCOUNTS.map((account) => (
                <button
                  key={account.role}
                  type="button"
                  onClick={() => chooseAccount(account)}
                  className="rounded-lg border border-transparent px-2 py-1.5 text-left transition hover:border-ink-600/60 hover:bg-ink-800/60"
                >
                  <span className="block text-[10px] font-medium text-slate-300">{ROLE_LABEL[account.role]}</span>
                  <span className="block truncate text-[9px] text-slate-600">{account.email}</span>
                </button>
              ))}
            </div>
            <p className="mt-3 border-t border-ink-600/40 pt-2.5 font-mono text-[10px] text-slate-600">
              password · {DEMO_PASSWORD}
            </p>
          </div>

          <p className="mt-5 text-center text-[10px] leading-relaxed text-slate-600">
            Access is logged and audited. Intelligence handling follows TLP markings and role clearance.
          </p>
        </div>
      </section>
    </div>
  );
}
