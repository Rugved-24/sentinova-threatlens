import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  KeyRound,
  Loader2,
  Plus,
  Search,
  ShieldCheck,
  ShieldOff,
  UserCog,
  UserPlus,
} from "lucide-react";
import { useState } from "react";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  Modal,
  PageHeader,
  SectionCard,
  Toggle,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { Role } from "../lib/types";
import { cn, formatDate, initials, ROLE_LABEL } from "../lib/utils";

const ROLES: Role[] = ["admin", "engineer", "responder", "hunter", "analyst", "executive"];

const ROLE_TONE: Record<Role, string> = {
  admin: "border-rose-400/25 bg-rose-500/8 text-rose-200",
  engineer: "border-violet/25 bg-violet/8 text-violet-200",
  responder: "border-amber-400/25 bg-amber-400/8 text-amber-200",
  hunter: "border-cyan-400/25 bg-cyan-400/8 text-cyan-200",
  analyst: "border-mint/25 bg-mint/8 text-emerald-200",
  executive: "border-slate-400/25 bg-slate-400/8 text-slate-300",
};

export function Users() {
  const { user: currentUser } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [query, setQuery] = useState("");
  const [createOpen, setCreateOpen] = useState(false);

  const users = useQuery({ queryKey: ["users"], queryFn: api.users });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => api.updateUser(id, body),
    onSuccess: () => {
      toast.success("User updated");
      void queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (error) => toast.error("Could not update user", error instanceof ApiError ? error.message : undefined),
  });

  const resetMfa = useMutation({
    mutationFn: (id: string) => api.resetMfa(id),
    onSuccess: () => {
      toast.success("MFA reset", "The user must enrol an authenticator on next setup.");
      void queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (error) => toast.error("Could not reset MFA", error instanceof ApiError ? error.message : undefined),
  });

  const rows = (users.data?.data ?? []).filter((user) => {
    const term = query.toLowerCase();
    return user.name.toLowerCase().includes(term) || user.email.toLowerCase().includes(term) || user.role.includes(term);
  });

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Access control"
        title="Users & roles"
        description="Manage operator accounts, role-based permissions and MFA enrolment. Administrators cannot deactivate or demote themselves."
        actions={
          <button type="button" className="btn-primary" onClick={() => setCreateOpen(true)}>
            <UserPlus className="h-4 w-4" /> Add user
          </button>
        }
      />

      <SectionCard title="Operator directory" subtitle={`${rows.length} accounts`} bodyClassName="p-0">
        <div className="border-b border-ink-600/40 p-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search name, email or role…"
              className="input h-9 py-1.5 pl-9 text-xs"
            />
          </div>
        </div>

        {users.isLoading ? (
          <div className="p-4"><LoadingPanel rows={6} /></div>
        ) : users.isError ? (
          <div className="p-4">
            <ErrorPanel
              message={users.error instanceof ApiError ? users.error.message : "Users could not be loaded"}
              retry={() => void users.refetch()}
            />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState title="No users match" description="Try a different name or role." icon={<UserCog className="h-5 w-5" />} />
        ) : (
          <div className="table-wrap rounded-none border-0">
            <table className="data-table min-w-[900px]">
              <thead>
                <tr>
                  <th>Operator</th>
                  <th>Role</th>
                  <th>MFA</th>
                  <th>Last login</th>
                  <th>Active</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <div className="flex items-center gap-2.5">
                        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400/20 to-violet/20 text-[10px] font-semibold text-cyan-100">
                          {initials(user.name)}
                        </span>
                        <div>
                          <p className="text-xs font-medium text-slate-200">
                            {user.name}
                            {user.id === currentUser?.id && <span className="ml-1.5 text-[9px] text-cyan-400">you</span>}
                          </p>
                          <p className="mt-0.5 text-[10px] text-slate-600">{user.email}</p>
                        </div>
                      </div>
                    </td>
                    <td>
                      <select
                        value={user.role}
                        onChange={(event) => update.mutate({ id: user.id, body: { role: event.target.value } })}
                        disabled={update.isPending}
                        className={cn("rounded-lg border px-2 py-1 text-[10px] font-medium outline-none", ROLE_TONE[user.role])}
                      >
                        {ROLES.map((role) => (
                          <option key={role} value={role} className="bg-ink-900 text-slate-200">
                            {ROLE_LABEL[role]}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <span className={cn("chip text-[9px]", user.mfa_enabled ? "border-mint/25 bg-mint/8 text-emerald-300" : "border-ink-600/60 bg-ink-800/50 text-slate-500")}>
                        {user.mfa_enabled ? <ShieldCheck className="h-3 w-3" /> : <ShieldOff className="h-3 w-3" />}
                        {user.mfa_enabled ? "enrolled" : "not set"}
                      </span>
                    </td>
                    <td className="whitespace-nowrap text-xs text-slate-500">{user.last_login_at ? formatDate(user.last_login_at) : "never"}</td>
                    <td>
                      <Toggle
                        checked={user.is_active}
                        onChange={(value) => update.mutate({ id: user.id, body: { is_active: value } })}
                        label={`Toggle ${user.name}`}
                        disabled={update.isPending || user.id === currentUser?.id}
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-ghost h-8 px-2 text-[10px]"
                        disabled={!user.mfa_enabled || resetMfa.isPending}
                        onClick={() => resetMfa.mutate(user.id)}
                      >
                        <KeyRound className="h-3 w-3" /> Reset MFA
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <div className="grid gap-4 md:grid-cols-2">
        <SectionCard title="Role model" subtitle="Least-privilege by default">
          <div className="space-y-1.5">
            {ROLES.map((role) => (
              <div key={role} className="flex items-center justify-between rounded-lg border border-ink-600/40 px-2.5 py-1.5">
                <span className={cn("chip text-[9px]", ROLE_TONE[role])}>{ROLE_LABEL[role]}</span>
                <span className="text-[10px] text-slate-600">
                  {rows.filter((user) => user.role === role).length} users
                </span>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Administrative safeguards" subtitle="Built into the API">
          <ul className="space-y-2 text-[11px] leading-relaxed text-slate-500">
            <li className="flex gap-2"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-mint" /> Self-deactivation and self-demotion are blocked.</li>
            <li className="flex gap-2"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-mint" /> The last active administrator cannot be removed.</li>
            <li className="flex gap-2"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-mint" /> Password resets revoke all active refresh sessions.</li>
            <li className="flex gap-2"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-mint" /> Every administrative action is written to the audit chain.</li>
          </ul>
        </SectionCard>
      </div>

      <CreateUserModal open={createOpen} onClose={() => setCreateOpen(false)} />
    </div>
  );
}

function CreateUserModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [password, setPassword] = useState("");

  const create = useMutation({
    mutationFn: () => api.createUser({ name: name.trim(), email: email.trim(), role, password }),
    onSuccess: (response) => {
      toast.success("User created", `${response.data.name} can now sign in.`);
      setName("");
      setEmail("");
      setPassword("");
      setRole("analyst");
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      onClose();
    },
    onError: (error) => toast.error("Could not create user", error instanceof ApiError ? error.message : undefined),
  });

  return (
    <Modal open={open} onClose={onClose} title="Add operator" description="Create an account with a role-scoped permission set.">
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label mb-1.5 block">Full name</label>
            <input value={name} onChange={(event) => setName(event.target.value)} className="input" placeholder="Jordan Lee" required minLength={2} />
          </div>
          <div>
            <label className="label mb-1.5 block">Role</label>
            <select value={role} onChange={(event) => setRole(event.target.value as Role)} className="select">
              {ROLES.map((item) => <option key={item} value={item}>{ROLE_LABEL[item]}</option>)}
            </select>
          </div>
        </div>
        <div>
          <label className="label mb-1.5 block">Email</label>
          <input value={email} onChange={(event) => setEmail(event.target.value)} type="email" className="input" placeholder="jordan.lee@threatlens.io" required />
        </div>
        <div>
          <label className="label mb-1.5 block">Initial password</label>
          <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" className="input font-mono text-xs" placeholder="At least 12 characters" required minLength={12} />
          <p className="mt-1 text-[10px] text-slate-600">Requires upper, lower, number and symbol. The user should rotate it after first login.</p>
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={create.isPending}>
            {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Create user
          </button>
        </div>
      </form>
    </Modal>
  );
}
