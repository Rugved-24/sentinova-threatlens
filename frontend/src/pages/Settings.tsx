import { useMutation } from "@tanstack/react-query";
import {
  Check,
  Copy,
  Fingerprint,
  KeyRound,
  Loader2,
  LockKeyhole,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  UserRound,
} from "lucide-react";
import { useState } from "react";
import { PageHeader, SectionCard } from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import { formatDate, ROLE_LABEL } from "../lib/utils";

export function Settings() {
  const { user, refreshUser } = useAuth();
  const toast = useToast();
  const [name, setName] = useState(user?.name ?? "");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaPassword, setMfaPassword] = useState("");
  const [setup, setSetup] = useState<{ secret: string; otpauth_url: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const profile = useMutation({
    mutationFn: () => api.profile({ name: name.trim() }),
    onSuccess: async () => {
      await refreshUser();
      toast.success("Profile updated");
    },
    onError: (error) => toast.error("Could not update profile", error instanceof ApiError ? error.message : undefined),
  });

  const password = useMutation({
    mutationFn: () => api.changePassword({ current_password: currentPassword, new_password: newPassword }),
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      toast.success("Password changed", "All other sessions have been revoked.");
    },
    onError: (error) => toast.error("Could not change password", error instanceof ApiError ? error.message : undefined),
  });

  const mfaSetup = useMutation({
    mutationFn: api.mfaSetup,
    onSuccess: (response) => {
      setSetup(response.data);
      setMfaCode("");
    },
    onError: (error) => toast.error("Could not start MFA setup", error instanceof ApiError ? error.message : undefined),
  });

  const mfaEnable = useMutation({
    mutationFn: () => api.mfaEnable(mfaCode),
    onSuccess: async () => {
      await refreshUser();
      setSetup(null);
      setMfaCode("");
      toast.success("Multi-factor authentication enabled");
    },
    onError: (error) => toast.error("Invalid authenticator code", error instanceof ApiError ? error.message : undefined),
  });

  const mfaDisable = useMutation({
    mutationFn: () => api.mfaDisable(mfaPassword, mfaCode),
    onSuccess: async () => {
      await refreshUser();
      setMfaPassword("");
      setMfaCode("");
      toast.success("Multi-factor authentication disabled");
    },
    onError: (error) => toast.error("Could not disable MFA", error instanceof ApiError ? error.message : undefined),
  });

  const copySecret = async () => {
    if (!setup) return;
    await navigator.clipboard.writeText(setup.secret);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  const passwordValid = newPassword.length >= 12 && newPassword === confirmPassword;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Account"
        title="Settings"
        description="Manage your profile, credentials and multi-factor authentication. Security changes are audited."
      />

      <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
        <div className="space-y-4">
          <SectionCard title="Profile" subtitle="Identity shown in the operations console">
            <div className="mb-5 flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-400/20 to-violet/20 text-lg font-semibold text-cyan-100">
                {user?.name.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-100">{user?.name}</p>
                <p className="mt-0.5 text-xs text-slate-500">{user?.email}</p>
                <div className="mt-1.5 flex items-center gap-1.5">
                  <span className="chip border-cyan-400/20 bg-cyan-400/8 text-[9px] text-cyan-200">
                    {user ? ROLE_LABEL[user.role] : ""}
                  </span>
                  <span className="text-[10px] text-slate-600">last login {formatDate(user?.last_login_at)}</span>
                </div>
              </div>
            </div>
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                if (name.trim().length >= 2) profile.mutate();
              }}
            >
              <div>
                <label className="label mb-1.5 block">Display name</label>
                <input value={name} onChange={(event) => setName(event.target.value)} className="input" minLength={2} required />
              </div>
              <div>
                <label className="label mb-1.5 block">Email</label>
                <input value={user?.email ?? ""} readOnly className="input cursor-not-allowed opacity-60" />
                <p className="mt-1 text-[10px] text-slate-600">Email changes require administrator action.</p>
              </div>
              <div className="flex justify-end">
                <button type="submit" className="btn-primary" disabled={profile.isPending || name.trim() === user?.name}>
                  {profile.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Save profile
                </button>
              </div>
            </form>
          </SectionCard>

          <SectionCard title="Password" subtitle="Rotate your credentials regularly">
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                if (passwordValid) password.mutate();
              }}
            >
              <div>
                <label className="label mb-1.5 block">Current password</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.target.value)}
                  className="input"
                  autoComplete="current-password"
                  required
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="label mb-1.5 block">New password</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                    className="input"
                    autoComplete="new-password"
                    minLength={12}
                    required
                  />
                </div>
                <div>
                  <label className="label mb-1.5 block">Confirm password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    className="input"
                    autoComplete="new-password"
                    required
                  />
                </div>
              </div>
              <div className="space-y-1">
                {[
                  ["At least 12 characters", newPassword.length >= 12],
                  ["Upper and lower case", /[A-Z]/.test(newPassword) && /[a-z]/.test(newPassword)],
                  ["Number and symbol", /\d/.test(newPassword) && /[^A-Za-z0-9]/.test(newPassword)],
                  ["Passwords match", newPassword.length > 0 && newPassword === confirmPassword],
                ].map(([label, valid]) => (
                  <p key={String(label)} className={`flex items-center gap-1.5 text-[10px] ${valid ? "text-emerald-300/80" : "text-slate-600"}`}>
                    <Check className={`h-3 w-3 ${valid ? "opacity-100" : "opacity-30"}`} /> {label}
                  </p>
                ))}
              </div>
              <div className="flex justify-end">
                <button type="submit" className="btn-primary" disabled={password.isPending || !passwordValid || !currentPassword}>
                  {password.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Change password
                </button>
              </div>
            </form>
          </SectionCard>
        </div>

        <div className="space-y-4">
          <SectionCard title="Multi-factor authentication" subtitle="Time-based one-time password">
            <div className={`mb-4 flex items-center gap-2 rounded-xl border px-3 py-2.5 ${user?.mfa_enabled ? "border-mint/25 bg-mint/[0.045]" : "border-amber-400/20 bg-amber-400/[0.04]"}`}>
              {user?.mfa_enabled ? (
                <ShieldCheck className="h-4 w-4 text-mint" />
              ) : (
                <ShieldOff className="h-4 w-4 text-amber-300" />
              )}
              <div>
                <p className={`text-xs font-medium ${user?.mfa_enabled ? "text-emerald-200" : "text-amber-200"}`}>
                  {user?.mfa_enabled ? "MFA is enabled" : "MFA is not configured"}
                </p>
                <p className="mt-0.5 text-[10px] text-slate-500">
                  {user?.mfa_enabled ? "A code is required at every sign-in." : "Strongly recommended for all operators."}
                </p>
              </div>
            </div>

            {user?.mfa_enabled ? (
              <form
                className="space-y-3"
                onSubmit={(event) => {
                  event.preventDefault();
                  mfaDisable.mutate();
                }}
              >
                <div>
                  <label className="label mb-1.5 block">Password</label>
                  <input type="password" value={mfaPassword} onChange={(event) => setMfaPassword(event.target.value)} className="input" required />
                </div>
                <div>
                  <label className="label mb-1.5 block">Authenticator code</label>
                  <input
                    value={mfaCode}
                    onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    className="input font-mono tracking-[0.35em]"
                    placeholder="000000"
                    inputMode="numeric"
                    required
                  />
                </div>
                <button type="submit" className="btn-danger w-full" disabled={mfaDisable.isPending || mfaCode.length !== 6 || !mfaPassword}>
                  {mfaDisable.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Disable MFA
                </button>
              </form>
            ) : setup ? (
              <div className="space-y-3">
                <div className="rounded-xl border border-ink-600/60 bg-ink-950/50 p-3">
                  <p className="mb-2 flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] text-slate-500">
                    <Smartphone className="h-3 w-3" /> Manual setup key
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 break-all rounded-lg bg-ink-800/70 px-2 py-1.5 font-mono text-[11px] text-cyan-200">
                      {setup.secret}
                    </code>
                    <button type="button" onClick={() => void copySecret()} className="btn-ghost h-8 px-2" aria-label="Copy secret">
                      {copied ? <Check className="h-3.5 w-3.5 text-mint" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-slate-600">
                    Add this key to your authenticator, or open the provisioning URI manually. The secret is shown only
                    during setup.
                  </p>
                </div>
                <div>
                  <label className="label mb-1.5 block">Verify code</label>
                  <input
                    value={mfaCode}
                    onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    className="input font-mono tracking-[0.35em]"
                    placeholder="000000"
                    inputMode="numeric"
                    autoFocus
                  />
                </div>
                <button
                  type="button"
                  className="btn-primary w-full"
                  disabled={mfaEnable.isPending || mfaCode.length !== 6}
                  onClick={() => mfaEnable.mutate()}
                >
                  {mfaEnable.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Enable MFA
                </button>
                <button type="button" className="w-full text-center text-[10px] text-slate-500 hover:text-slate-300" onClick={() => setSetup(null)}>
                  Cancel setup
                </button>
              </div>
            ) : (
              <button type="button" className="btn-primary w-full" onClick={() => mfaSetup.mutate()} disabled={mfaSetup.isPending}>
                {mfaSetup.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                Configure authenticator
              </button>
            )}
          </SectionCard>

          <SectionCard title="Security posture" subtitle="Your current access envelope">
            <div className="space-y-3">
              {[
                { icon: UserRound, label: "Role", value: user ? ROLE_LABEL[user.role] : "—" },
                { icon: Fingerprint, label: "MFA", value: user?.mfa_enabled ? "Enrolled" : "Not enrolled" },
                { icon: LockKeyhole, label: "Session", value: "Access token in memory" },
                { icon: ShieldCheck, label: "Audit", value: "All actions recorded" },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.label} className="flex items-center justify-between rounded-lg border border-ink-600/40 px-2.5 py-2">
                    <span className="flex items-center gap-2 text-[11px] text-slate-500">
                      <Icon className="h-3.5 w-3.5 text-cyan-400/70" /> {item.label}
                    </span>
                    <span className="text-[11px] text-slate-300">{item.value}</span>
                  </div>
                );
              })}
            </div>
            <p className="mt-3 text-[10px] leading-relaxed text-slate-600">
              TLP clearance is determined by role. Executive accounts receive aggregate reporting without raw indicator
              values.
            </p>
          </SectionCard>
        </div>
      </div>
    </div>
  );
}
