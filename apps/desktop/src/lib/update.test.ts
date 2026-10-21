import { beforeEach, describe, expect, it, vi } from "vitest";
import type { UpdateState } from "./types";

const invoke = vi.hoisted(() => vi.fn());
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return () => handlers.delete(name);
  }),
}));

import {
  formatProgress,
  formatReleaseDate,
  isBusy,
  progressPercent,
  updateSummary,
  UpdateStore,
} from "./update.svelte";

const available: UpdateState = {
  state: "available",
  version: "0.3.0",
  notes: "Fixes",
  date: "2026-10-20T10:00:00Z",
  installable: true,
  release_url: "https://github.com/adithyaharun/wyvpn/releases/tag/v0.3.0",
};
const dismissed: UpdateState = { ...available, state: "dismissed" };

function emit(name: string, payload: unknown) {
  const handler = handlers.get(name);
  if (!handler) throw new Error(`no listener for ${name}`);
  handler({ payload });
}

async function started(initial: UpdateState = { state: "idle" }) {
  invoke.mockImplementation(async (command: string) => (command === "update_state" ? initial : null));
  const store = new UpdateStore();
  const stop = store.start();
  await vi.waitFor(() => expect(handlers.has("app://update-prompt")).toBe(true));
  await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("update_state", undefined));
  return { store, stop };
}

describe("update helpers", () => {
  it("computes a percentage only when the total is known", () => {
    expect(progressPercent(250, 1000)).toBe(25);
    expect(progressPercent(999, 1000)).toBe(99);
    expect(progressPercent(2000, 1000)).toBe(100);
    expect(progressPercent(10, null)).toBeNull();
    expect(progressPercent(10, 0)).toBeNull();
  });

  it("formats progress with and without a total", () => {
    expect(formatProgress(1_500_000, 6_000_000)).toBe("1.5 MB of 6.0 MB (25%)");
    expect(formatProgress(1_500_000, null)).toBe("1.5 MB");
  });

  it("formats a release date and ignores invalid ones", () => {
    expect(formatReleaseDate("2026-10-20T10:00:00Z")).toMatch(/2026/);
    expect(formatReleaseDate("soon")).toBeNull();
    expect(formatReleaseDate(null)).toBeNull();
  });

  it("treats checks and installs as busy", () => {
    expect(isBusy({ state: "checking" })).toBe(true);
    expect(isBusy({ state: "downloading", version: "1", received: 0, total: null })).toBe(true);
    expect(isBusy({ state: "relaunching", version: "1" })).toBe(true);
    expect(isBusy(available)).toBe(false);
    expect(isBusy({ state: "failed", message: "x" })).toBe(false);
  });

  it("summarizes each result", () => {
    expect(updateSummary({ state: "idle" })).toBeNull();
    expect(updateSummary({ state: "up_to_date" })).toBe("WyVPN is up to date.");
    expect(updateSummary(available)).toBe("Version 0.3.0 is available.");
    expect(updateSummary({ state: "failed", message: "Could not reach the update server." })).toBe(
      "Could not reach the update server.",
    );
  });
});

describe("UpdateStore", () => {
  beforeEach(() => {
    handlers.clear();
    invoke.mockReset();
  });

  it("opens when the backend already has an undismissed update", async () => {
    const { store, stop } = await started(available);
    await vi.waitFor(() => expect(store.open).toBe(true));
    stop();
  });

  it("stays closed for a dismissed update", async () => {
    const { store, stop } = await started(dismissed);
    await vi.waitFor(() => expect(store.state.state).toBe("dismissed"));
    expect(store.open).toBe(false);
    stop();
  });

  it("follows state events and opens when an update is found", async () => {
    const { store, stop } = await started();
    emit("app://update", { state: "checking" });
    expect(store.state.state).toBe("checking");
    expect(store.open).toBe(false);
    emit("app://update", available);
    expect(store.open).toBe(true);
    stop();
  });

  it("asks the backend again when the window is shown", async () => {
    const { store, stop } = await started(dismissed);
    invoke.mockImplementation(async (command: string) =>
      command === "update_state" ? { ...available, version: "0.3.1" } : null,
    );
    window.dispatchEvent(new Event("focus"));
    await vi.waitFor(() => expect(store.open).toBe(true));
    stop();
  });

  it("does not reopen a dismissed version when the window is shown", async () => {
    const { store, stop } = await started(dismissed);
    invoke.mockImplementation(async (command: string) => (command === "update_state" ? available : null));
    window.dispatchEvent(new Event("focus"));
    await vi.waitFor(() => expect(store.state.state).toBe("available"));
    expect(store.open).toBe(false);
    stop();
  });

  describe("closing during an automatic check", () => {
    async function closedWhileChecking(dismiss: () => Promise<UpdateState>) {
      const { store, stop } = await started(available);
      await vi.waitFor(() => expect(store.open).toBe(true));
      invoke.mockImplementation(async (command: string) => (command === "dismiss_update" ? dismiss() : null));
      emit("app://update", { state: "checking" });
      store.close();
      expect(store.open).toBe(false);
      await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("dismiss_update", undefined));
      return { store, stop };
    }

    it("dismisses the offer that was showing", async () => {
      const { store, stop } = await closedWhileChecking(async () => ({ state: "checking" }));
      emit("app://update", dismissed);
      expect(store.open).toBe(false);
      stop();
    });

    it("keeps the sheet closed when the same version comes back available", async () => {
      const { store, stop } = await closedWhileChecking(async () => {
        throw { code: "invalid_request", message: "there is no update to dismiss" };
      });
      emit("app://update", available);
      expect(store.state.state).toBe("available");
      expect(store.open).toBe(false);
      expect(store.error).toBeNull();
      stop();
    });

    it("opens again for a newer version", async () => {
      const { store, stop } = await closedWhileChecking(async () => ({ state: "checking" }));
      emit("app://update", { ...available, version: "0.3.1" });
      expect(store.open).toBe(true);
      stop();
    });
  });

  it("does not dismiss when closed during a check that had no offer", async () => {
    const { store, stop } = await started({ state: "up_to_date" });
    store.show();
    emit("app://update", { state: "checking" });
    store.close();
    expect(store.open).toBe(false);
    expect(invoke).not.toHaveBeenCalledWith("dismiss_update", undefined);
    stop();
  });

  it("offers the same version again after a failed install", async () => {
    const { store, stop } = await started(available);
    await vi.waitFor(() => expect(store.open).toBe(true));
    emit("app://update", { state: "disconnecting", version: "0.3.0" });
    emit("app://update", { state: "failed", message: "The update could not be downloaded." });
    store.close();
    expect(store.open).toBe(false);
    expect(invoke).not.toHaveBeenCalledWith("dismiss_update", undefined);

    emit("app://update", { state: "checking" });
    emit("app://update", available);
    expect(store.open).toBe(true);
    stop();
  });

  it("ignores a malformed state", async () => {
    invoke.mockImplementation(async () => null);
    const store = new UpdateStore();
    const stop = store.start();
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("update_state", undefined));
    await Promise.resolve();
    expect(store.state).toEqual({ state: "idle" });
    stop();
  });

  it("opens for prompts from the tray or app menu", async () => {
    const { store, stop } = await started();
    emit("app://update", { state: "up_to_date" });
    emit("app://update-prompt", { outcome: "up_to_date" });
    expect(store.open).toBe(true);
    stop();
  });

  it("keeps the result of its own check inline unless an update is found", async () => {
    const { store, stop } = await started();
    invoke.mockImplementation(async (command: string) => {
      if (command !== "check_for_updates") return null;
      emit("app://update", { state: "up_to_date" });
      emit("app://update-prompt", { outcome: "up_to_date" });
      return { state: "up_to_date" };
    });
    await store.check();
    expect(store.state.state).toBe("up_to_date");
    expect(store.open).toBe(false);

    invoke.mockImplementation(async (command: string) => {
      if (command !== "check_for_updates") return null;
      emit("app://update", available);
      emit("app://update-prompt", { outcome: "available" });
      return available;
    });
    await store.check();
    expect(store.open).toBe(true);
    stop();
  });

  it("shows a rejected check without swallowing the next prompt", async () => {
    const { store, stop } = await started();
    invoke.mockImplementation(async (command: string) => {
      if (command === "check_for_updates") throw { code: "invalid_request", message: "an update is already in progress" };
      return null;
    });
    await store.check();
    expect(store.error).toBe("an update is already in progress");

    emit("app://update-prompt", { outcome: "failed" });
    expect(store.open).toBe(true);
    stop();
  });

  it("Later dismisses an available update and closes", async () => {
    const { store, stop } = await started(available);
    await vi.waitFor(() => expect(store.open).toBe(true));
    invoke.mockImplementation(async (command: string) => (command === "dismiss_update" ? dismissed : null));
    await store.later();
    expect(invoke).toHaveBeenCalledWith("dismiss_update", undefined);
    expect(store.open).toBe(false);
    expect(store.state.state).toBe("dismissed");
    stop();
  });

  it("closes a dismissed offer without calling the backend", async () => {
    const { store, stop } = await started(dismissed);
    await vi.waitFor(() => expect(store.state.state).toBe("dismissed"));
    store.show();
    store.close();
    expect(store.open).toBe(false);
    expect(invoke).not.toHaveBeenCalledWith("dismiss_update", undefined);
    stop();
  });

  it("cannot be closed while installing", async () => {
    const { store, stop } = await started(available);
    emit("app://update", { state: "downloading", version: "0.3.0", received: 1, total: 2 });
    store.close();
    expect(store.open).toBe(true);
    stop();
  });

  it("reports an install that the backend rejects", async () => {
    const { store, stop } = await started(available);
    invoke.mockImplementation(async (command: string) => {
      if (command === "install_update") throw { code: "invalid_request", message: "there is no update to install" };
      return null;
    });
    await store.install();
    expect(invoke).toHaveBeenCalledWith("install_update", undefined);
    expect(store.error).toBe("there is no update to install");
    stop();
  });

  it("stops listening when disposed", async () => {
    const { stop } = await started();
    stop();
    expect(handlers.size).toBe(0);
  });
});
