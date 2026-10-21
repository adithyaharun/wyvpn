import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { api } from "./api";
import { describeError, toCommandError } from "./errors";
import { formatBytes } from "./format";
import type { UpdateOffer, UpdatePrompt, UpdateState } from "./types";

export const UPDATE_CHANNEL = "app://update";
export const PROMPT_CHANNEL = "app://update-prompt";

export function isInstalling(state: UpdateState): boolean {
  return (
    state.state === "disconnecting" ||
    state.state === "downloading" ||
    state.state === "installing" ||
    state.state === "relaunching"
  );
}

export function isBusy(state: UpdateState): boolean {
  return state.state === "checking" || isInstalling(state);
}

export function offerOf(state: UpdateState): UpdateOffer | null {
  return state.state === "available" || state.state === "dismissed" ? state : null;
}

export function progressPercent(received: number, total: number | null): number | null {
  if (total === null || !(total > 0)) return null;
  return Math.min(100, Math.max(0, Math.floor((received / total) * 100)));
}

export function formatProgress(received: number, total: number | null): string {
  const percent = progressPercent(received, total);
  if (percent === null || total === null) return formatBytes(received);
  return `${formatBytes(received)} of ${formatBytes(total)} (${percent}%)`;
}

export function formatReleaseDate(date: string | null): string | null {
  if (!date) return null;
  const parsed = new Date(date);
  if (Number.isNaN(parsed.getTime())) return null;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(parsed);
}

export function updateSummary(state: UpdateState): string | null {
  switch (state.state) {
    case "idle":
      return null;
    case "checking":
      return "Checking for updates…";
    case "up_to_date":
      return "WyVPN is up to date.";
    case "available":
    case "dismissed":
      return `Version ${state.version} is available.`;
    case "disconnecting":
    case "downloading":
    case "installing":
      return `Installing version ${state.version}…`;
    case "relaunching":
      return "Restarting WyVPN…";
    case "failed":
      return state.message || "The update check failed.";
  }
}

export class UpdateStore {
  state = $state.raw<UpdateState>({ state: "idle" });
  open = $state(false);
  error = $state.raw<string | null>(null);

  #seq = 0;
  // Manual checks started here show their result inline, so only "available" opens the sheet.
  #quietPrompts = 0;
  #undismissed: string | null = null;
  #declined: string | null = null;

  get busy(): boolean {
    return isBusy(this.state);
  }

  get installing(): boolean {
    return isInstalling(this.state);
  }

  start(): () => void {
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];
    const onShown = () => {
      if (document.visibilityState !== "hidden") void this.refresh();
    };

    Promise.all([
      listen<UpdateState>(UPDATE_CHANNEL, ({ payload }) => {
        this.#seq++;
        this.#apply(payload);
      }),
      listen<UpdatePrompt>(PROMPT_CHANNEL, ({ payload }) => this.#prompt(payload)),
    ])
      .then((subscriptions) => {
        if (disposed) subscriptions.forEach((off) => off());
        else unlisteners.push(...subscriptions);
        if (!disposed) void this.refresh();
      })
      .catch(() => {});
    window.addEventListener("focus", onShown);
    document.addEventListener("visibilitychange", onShown);

    return () => {
      disposed = true;
      unlisteners.forEach((off) => off());
      window.removeEventListener("focus", onShown);
      document.removeEventListener("visibilitychange", onShown);
    };
  }

  async refresh(): Promise<void> {
    const seq = this.#seq;
    try {
      const next = await api.updateState();
      if (seq === this.#seq) this.#apply(next);
    } catch {}
  }

  async check(): Promise<void> {
    if (this.busy) return;
    this.error = null;
    this.#quietPrompts++;
    const seq = this.#seq;
    try {
      const next = await api.checkForUpdates();
      if (seq === this.#seq) this.#apply(next);
    } catch (raw) {
      this.#quietPrompts = Math.max(0, this.#quietPrompts - 1);
      this.#fail(raw);
    }
  }

  async install(): Promise<void> {
    if (this.busy) return;
    this.error = null;
    try {
      await api.installUpdate();
    } catch (raw) {
      this.#fail(raw);
    }
  }

  async later(): Promise<void> {
    this.open = false;
    this.error = null;
    const version = this.state.state === "available" ? this.state.version : this.#undismissed;
    if (version === null) return;
    this.#declined = version;
    this.#undismissed = null;
    if (this.state.state !== "available" && this.state.state !== "checking") return;
    const seq = this.#seq;
    try {
      const next = await api.dismissUpdate();
      if (seq === this.#seq) this.#apply(next);
    } catch {
      // A concurrent state change can reject the dismiss; #declined still keeps the sheet closed.
    }
  }

  async openPage(): Promise<void> {
    this.error = null;
    try {
      await api.openUpdatePage();
    } catch {
      this.error = "WyVPN couldn't open your browser. Try again.";
      return;
    }
    await this.later();
  }

  show(): void {
    this.open = true;
  }

  close(): void {
    if (!this.installing) void this.later();
  }

  #apply(next: UpdateState | null): void {
    if (typeof next !== "object" || next === null || typeof next.state !== "string") return;
    this.state = next;
    if (next.state === "available") {
      this.#undismissed = next.version;
      if (next.version !== this.#declined) this.open = true;
    } else if (next.state === "dismissed") {
      this.#undismissed = null;
      this.#declined = next.version;
    } else if (next.state !== "checking") {
      this.#undismissed = null;
    }
  }

  #prompt({ outcome }: UpdatePrompt): void {
    const quiet = this.#quietPrompts > 0;
    if (quiet) this.#quietPrompts--;
    if (outcome === "available" || !quiet) this.open = true;
  }

  #fail(raw: unknown): void {
    this.error = describeError(toCommandError(raw).toBody());
  }
}

export const updates = new UpdateStore();
