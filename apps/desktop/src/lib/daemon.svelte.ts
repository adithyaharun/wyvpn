import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { api } from "./api";
import { toCommandError } from "./errors";
import {
  activeSession,
  applyEvent,
  initialState,
  type DaemonState,
  type LogState,
  type StoreEvent,
} from "./reducer";
import type {
  BusyAction,
  ConnectionStatus,
  DaemonAvailability,
  DaemonEvent,
  DaemonStatus,
  ServiceStatus,
  VersionMismatch,
  ErrorBody,
  PendingCredentials,
  ProfileSummary,
  Transport,
} from "./types";

export { applyEvent, initialState, activeSession, isActive } from "./reducer";
export type { DaemonState, LogState, StoreEvent } from "./reducer";

type LogBatch = Extract<StoreEvent, { type: "log" }>;

export class DaemonStore {
  #state = $state.raw<DaemonState>(initialState());
  #profilesSeq = 0;
  #statusSeq = 0;
  #logFetch: Promise<void> | null = null;
  #logReplay: LogBatch[] = [];

  busy = $state.raw<Record<string, BusyAction>>({});
  lastError = $state.raw<ErrorBody | null>(null);
  logError = $state.raw<ErrorBody | null>(null);

  get state(): DaemonState {
    return this.#state;
  }
  get available(): boolean {
    return this.#state.available;
  }
  get status(): DaemonStatus {
    return this.#state.status;
  }
  get mismatch(): VersionMismatch | null {
    return this.#state.mismatch;
  }
  get setup(): ServiceStatus | null {
    return this.#state.setup;
  }
  get socket(): string {
    return this.#state.socket;
  }
  get profiles(): ProfileSummary[] {
    return this.#state.profiles;
  }
  get statuses(): Record<string, ConnectionStatus> {
    return this.#state.statuses;
  }
  get pendingCredentials(): PendingCredentials | null {
    return this.#state.pendingCredentials;
  }
  get session(): ConnectionStatus | null {
    return activeSession(this.#state);
  }
  get log(): LogState {
    return this.#state.log;
  }

  dispatch(event: StoreEvent): void {
    // A status fetched before the prompt opened would close it again.
    if (event.type === "credentials_required") this.#statusSeq++;
    this.#state = applyEvent(this.#state, event);
    if (event.type === "availability" && event.available) void this.refresh();
    if (event.type === "state_changed") void this.refreshStatus();
    if (event.type === "log") {
      if (this.#logFetch) this.#logReplay.push(event);
      else if (this.#state.log.stale || this.logError !== null) void this.refreshLog();
    }
  }

  start(): () => void {
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];

    const boot = async () => {
      const subscriptions = await Promise.all([
        listen<DaemonEvent>("daemon://event", ({ payload }) => this.dispatch(payload)),
        listen<DaemonAvailability>("daemon://availability", ({ payload }) =>
          this.dispatch({ type: "availability", ...payload }),
        ),
        listen<ConnectionStatus[]>("daemon://statuses", ({ payload }) => {
          this.#statusSeq++;
          this.dispatch({ type: "statuses", statuses: payload });
        }),
        listen<ProfileSummary[]>("daemon://profiles", ({ payload }) => {
          this.#profilesSeq++;
          this.dispatch({ type: "profiles", profiles: payload });
        }),
      ]);
      if (disposed) {
        subscriptions.forEach((unlisten) => unlisten());
        return;
      }
      unlisteners.push(...subscriptions);
      const availability = await api.daemonState();
      if (!disposed) this.dispatch({ type: "availability", ...availability });
    };
    boot().catch((error) => this.#fail(error));

    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }

  async refreshAvailability(): Promise<void> {
    try {
      this.dispatch({ type: "availability", ...(await api.daemonState()) });
    } catch (error) {
      this.#failQuietly(error);
    }
  }

  async refresh(): Promise<void> {
    await Promise.all([this.refreshProfiles(), this.refreshStatus()]);
  }

  async refreshProfiles(): Promise<void> {
    const seq = ++this.#profilesSeq;
    try {
      const profiles = await api.listProfiles();
      if (seq === this.#profilesSeq) this.dispatch({ type: "profiles", profiles });
    } catch (error) {
      this.#failQuietly(error);
    }
  }

  async refreshStatus(): Promise<void> {
    const seq = ++this.#statusSeq;
    try {
      const statuses = await api.status();
      if (seq === this.#statusSeq) this.dispatch({ type: "statuses", statuses });
    } catch (error) {
      this.#failQuietly(error);
    }
  }

  refreshLog(): Promise<void> {
    this.#logFetch ??= this.#fetchLog().finally(() => {
      this.#logFetch = null;
      this.#logReplay = [];
    });
    return this.#logFetch;
  }

  async #fetchLog(): Promise<void> {
    this.#logReplay = [];
    try {
      const log = await api.sessionLog();
      this.logError = null;
      let next = applyEvent(this.#state, { type: "log_loaded", ...log });
      for (const batch of this.#logReplay) next = applyEvent(next, batch);
      this.#state = next;
    } catch (error) {
      this.logError = toCommandError(error).toBody();
    }
  }

  async rename(profileId: string, name: string): Promise<ProfileSummary> {
    const profile = await api.renameProfile(profileId, name);
    this.#profilesSeq++;
    this.#state = applyEvent(this.#state, { type: "profile_updated", profile });
    return profile;
  }

  connect(profileId: string, transport?: Transport): Promise<void> {
    return this.#run(profileId, "connect", async () => {
      await api.connect(profileId, transport);
      await this.refreshStatus();
    });
  }

  disconnect(profileId: string): Promise<void> {
    return this.#run(profileId, "disconnect", async () => {
      await api.disconnect(profileId);
      await this.refreshStatus();
    });
  }

  remove(profileId: string): Promise<void> {
    return this.#run(profileId, "remove", async () => {
      await api.removeProfile(profileId);
      await this.refresh();
    });
  }

  async submitPin(profileId: string, pin: string): Promise<void> {
    this.lastError = null;
    this.#state = applyEvent(this.#state, { type: "credentials_cleared", profile_id: profileId });
    try {
      await api.submitPin(profileId, pin);
    } catch (error) {
      this.#fail(error);
    }
  }

  async cancelCredentials(profileId: string): Promise<void> {
    this.#state = applyEvent(this.#state, { type: "credentials_cleared", profile_id: profileId });
    try {
      await api.cancelCredentials(profileId);
    } catch (error) {
      this.#fail(error);
    }
  }

  async importFile(replace: boolean): Promise<ProfileSummary[] | null> {
    const imported = await api.importFile(replace);
    if (imported) await this.refreshProfiles();
    return imported;
  }

  async importLink(link: string, replace: boolean): Promise<ProfileSummary[]> {
    const imported = await api.importLink(link, replace);
    await this.refreshProfiles();
    return imported;
  }

  async replaceImport(retry: string): Promise<ProfileSummary[]> {
    const imported = await api.replaceImport(retry);
    await this.refreshProfiles();
    return imported;
  }

  dismissError(): void {
    this.lastError = null;
  }

  async #run(profileId: string, action: BusyAction, task: () => Promise<void>): Promise<void> {
    if (this.busy[profileId]) return;
    this.lastError = null;
    this.busy = { ...this.busy, [profileId]: action };
    try {
      await task();
    } catch (error) {
      this.#fail(error);
    } finally {
      const rest = { ...this.busy };
      delete rest[profileId];
      this.busy = rest;
    }
  }

  #fail(error: unknown): void {
    this.lastError = toCommandError(error).toBody();
  }

  #failQuietly(error: unknown): void {
    const body = toCommandError(error).toBody();
    if (body.code !== "daemon_unavailable") this.lastError = body;
  }
}

export const daemon = new DaemonStore();
