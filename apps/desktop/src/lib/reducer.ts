import type {
  ConnectionState,
  ConnectionStatus,
  DaemonEvent,
  LogLine,
  PendingCredentials,
  ProfileSummary,
  DaemonAvailability,
  DaemonStatus,
  ServiceStatus,
  VersionMismatch,
} from "./types";

export const LOG_CAPACITY = 1000;

export interface LogState {
  profileId: string | null;
  lines: LogLine[];
  stale: boolean;
}

export interface DaemonState {
  available: boolean;
  status: DaemonStatus;
  mismatch: VersionMismatch | null;
  setup: ServiceStatus | null;
  socket: string;
  profiles: ProfileSummary[];
  statuses: Record<string, ConnectionStatus>;
  pendingCredentials: PendingCredentials | null;
  suppressedAwaiting: readonly string[];
  log: LogState;
  lastProfileId: string | null;
}

export type StoreEvent =
  | DaemonEvent
  | ({ type: "availability" } & DaemonAvailability)
  | { type: "profiles"; profiles: ProfileSummary[] }
  | { type: "statuses"; statuses: ConnectionStatus[] }
  | { type: "credentials_cleared"; profile_id: string }
  | { type: "profile_updated"; profile: ProfileSummary }
  | { type: "log_loaded"; profile_id: string | null; lines: LogLine[] };

export const ACTIVE_STATES: readonly ConnectionState[] = ["connecting", "connected", "disconnecting"];

export function isActive(state: ConnectionState | undefined): boolean {
  return state !== undefined && ACTIVE_STATES.includes(state);
}

export function initialState(): DaemonState {
  return {
    available: false,
    status: "unreachable",
    mismatch: null,
    setup: null,
    socket: "",
    profiles: [],
    statuses: {},
    pendingCredentials: null,
    suppressedAwaiting: [],
    log: { profileId: null, lines: [], stale: true },
    lastProfileId: null,
  };
}

function blankStatus(profileId: string, profiles: ProfileSummary[]): ConnectionStatus {
  return {
    profile_id: profileId,
    profile_name: profiles.find((p) => p.id === profileId)?.name ?? "",
    state: "disconnected",
    transport: null,
    tunnel_ip: null,
    server_endpoint: null,
    connected_since: null,
    rx_bytes: 0,
    tx_bytes: 0,
    error: null,
  };
}

function clearPending(state: DaemonState, profileId: string): PendingCredentials | null {
  return state.pendingCredentials?.profileId === profileId ? null : state.pendingCredentials;
}

function reconcilePending(
  pending: PendingCredentials | null,
  statuses: Record<string, ConnectionStatus>,
  suppressed: readonly string[],
): PendingCredentials | null {
  if (pending) {
    const status = statuses[pending.profileId];
    return status?.awaiting || status?.state === "connecting" ? pending : null;
  }
  const awaiting = Object.values(statuses).find((s) => s.awaiting && !suppressed.includes(s.profile_id));
  return awaiting?.awaiting ? { profileId: awaiting.profile_id, mode: awaiting.awaiting } : null;
}

function capped(lines: LogLine[]): LogLine[] {
  return lines.length > LOG_CAPACITY ? lines.slice(lines.length - LOG_CAPACITY) : lines;
}

function appendLog(log: LogState, profileId: string, incoming: LogLine[]): LogState {
  const first = incoming[0];
  if (!first) return log;
  if (log.profileId !== profileId) {
    return { profileId, lines: capped(incoming), stale: log.profileId !== null || first.seq !== 0 };
  }
  const last = log.lines.at(-1);
  if (last && first.seq <= last.seq) {
    const known = log.lines.find((line) => line.seq === first.seq);
    if (known && known.at_ms === first.at_ms && known.text === first.text) {
      const fresh = incoming.filter((line) => line.seq > last.seq);
      return fresh.length === 0 ? log : { ...log, lines: capped([...log.lines, ...fresh]) };
    }
  }
  // The daemon restarts the sequence at zero when a new session clears the log.
  if (first.seq === 0) return { profileId, lines: capped(incoming), stale: false };
  if (!last || first.seq <= last.seq) return { profileId, lines: capped(incoming), stale: true };
  return {
    profileId,
    lines: capped([...log.lines, ...incoming]),
    stale: log.stale || first.seq !== last.seq + 1,
  };
}

export function applyEvent(state: DaemonState, event: StoreEvent): DaemonState {
  switch (event.type) {
    case "availability":
      return {
        ...state,
        available: event.available,
        status: event.status ?? (event.available ? "available" : "unreachable"),
        mismatch: event.mismatch ?? null,
        setup: event.setup ?? null,
        socket: event.socket,
        pendingCredentials: event.available ? state.pendingCredentials : null,
        suppressedAwaiting: event.available ? state.suppressedAwaiting : [],
      };

    case "profiles": {
      const ids = new Set(event.profiles.map((p) => p.id));
      const pending = state.pendingCredentials;
      return {
        ...state,
        profiles: event.profiles,
        pendingCredentials: pending && ids.has(pending.profileId) ? pending : null,
        suppressedAwaiting: state.suppressedAwaiting.filter((id) => ids.has(id)),
      };
    }

    case "statuses": {
      const statuses = Object.fromEntries(event.statuses.map((s) => [s.profile_id, s]));
      const suppressedAwaiting = state.suppressedAwaiting.filter((id) => statuses[id]?.awaiting);
      return {
        ...state,
        statuses,
        suppressedAwaiting,
        pendingCredentials: reconcilePending(state.pendingCredentials, statuses, suppressedAwaiting),
      };
    }

    case "state_changed": {
      const previous = state.statuses[event.profile_id] ?? blankStatus(event.profile_id, state.profiles);
      const error = event.error ?? (event.state === "error" ? previous.error : null);
      const next: ConnectionStatus = {
        ...previous,
        state: event.state,
        error,
        connected_since: event.state === "connected" ? previous.connected_since : null,
      };
      return {
        ...state,
        statuses: { ...state.statuses, [event.profile_id]: next },
        lastProfileId: event.profile_id,
        pendingCredentials:
          event.state === "connecting" ? state.pendingCredentials : clearPending(state, event.profile_id),
      };
    }

    case "credentials_required":
      return {
        ...state,
        pendingCredentials: { profileId: event.profile_id, mode: event.mode },
        lastProfileId: event.profile_id,
        suppressedAwaiting: state.suppressedAwaiting.filter((id) => id !== event.profile_id),
      };

    case "credentials_cleared":
      return {
        ...state,
        pendingCredentials: clearPending(state, event.profile_id),
        suppressedAwaiting: state.suppressedAwaiting.includes(event.profile_id)
          ? state.suppressedAwaiting
          : [...state.suppressedAwaiting, event.profile_id],
      };

    case "profiles_changed":
      return state;

    case "profile_updated": {
      const { profile } = event;
      if (!state.profiles.some((p) => p.id === profile.id)) return state;
      const status = state.statuses[profile.id];
      return {
        ...state,
        profiles: state.profiles.map((p) => (p.id === profile.id ? profile : p)),
        statuses: status
          ? { ...state.statuses, [profile.id]: { ...status, profile_name: profile.name } }
          : state.statuses,
      };
    }

    case "log":
      return { ...state, log: appendLog(state.log, event.profile_id, event.lines) };

    case "log_loaded":
      return { ...state, log: { profileId: event.profile_id, lines: capped(event.lines), stale: false } };

    case "stats": {
      const previous = state.statuses[event.profile_id];
      if (!previous) return state;
      return {
        ...state,
        statuses: {
          ...state.statuses,
          [event.profile_id]: { ...previous, rx_bytes: event.rx_bytes, tx_bytes: event.tx_bytes },
        },
      };
    }
  }
}

export function activeSession(state: DaemonState): ConnectionStatus | null {
  const all = Object.values(state.statuses);
  const active = all.find((s) => isActive(s.state));
  if (active) return active;
  const last = state.lastProfileId ? state.statuses[state.lastProfileId] : undefined;
  if (last) return last.state === "error" ? last : null;
  return all.find((s) => s.state === "error") ?? null;
}
