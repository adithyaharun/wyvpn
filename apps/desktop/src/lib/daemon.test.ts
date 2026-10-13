import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionStatus, LogLine, ProfileSummary } from "./types";

const invoke = vi.hoisted(() => vi.fn());
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return () => handlers.delete(name);
  }),
}));

import { DaemonStore } from "./daemon.svelte";

const office: ProfileSummary = {
  id: "p1",
  name: "Office",
  server_name: "gw",
  server_host: "vpn.example.com",
  user: "alice",
  auth_mode: "pin",
  transports: ["wire_guard"],
};

const awaiting: ConnectionStatus = {
  profile_id: "p1",
  profile_name: "Office",
  state: "connecting",
  transport: null,
  tunnel_ip: null,
  server_endpoint: null,
  connected_since: null,
  rx_bytes: 0,
  tx_bytes: 0,
  awaiting: "pin",
};

function emit(name: string, payload: unknown) {
  const handler = handlers.get(name);
  if (!handler) throw new Error(`no listener for ${name}`);
  handler({ payload });
}

describe("DaemonStore", () => {
  let store: DaemonStore;
  let stop: () => void;

  beforeEach(async () => {
    handlers.clear();
    invoke.mockReset();
    invoke.mockImplementation(async (command: string) => {
      if (command === "daemon_state") return { available: true, socket: "/tmp/w.sock" };
      if (command === "list_profiles") return [office];
      if (command === "status") return [];
      return null;
    });
    store = new DaemonStore();
    stop = store.start();
    await vi.waitFor(() => expect(store.profiles).toEqual([office]));
  });

  afterEach(() => stop());

  it("applies pushed statuses and profiles", () => {
    emit("daemon://statuses", [{ ...awaiting, state: "connected", awaiting: undefined }]);
    expect(store.session?.state).toBe("connected");

    emit("daemon://profiles", []);
    expect(store.profiles).toEqual([]);
  });

  it("restores a prompt from a heartbeat", () => {
    emit("daemon://statuses", [awaiting]);
    expect(store.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });
  });

  it("does not re-open the prompt after submit", async () => {
    emit("daemon://statuses", [awaiting]);
    await store.submitPin("p1", "4321");
    emit("daemon://statuses", [awaiting]);

    expect(store.pendingCredentials).toBeNull();
    expect(invoke).toHaveBeenCalledWith("submit_pin", { profileId: "p1", pin: "4321" });
    expect(JSON.stringify(store.state)).not.toContain("4321");
  });

  it("does not re-open the prompt after cancel", async () => {
    emit("daemon://statuses", [awaiting]);
    await store.cancelCredentials("p1");
    emit("daemon://statuses", [awaiting]);

    expect(store.pendingCredentials).toBeNull();
    expect(invoke).toHaveBeenCalledWith("cancel_credentials", { profileId: "p1" });
  });

  it("ignores a status fetched before a prompt opened", async () => {
    let resolveStatus: (statuses: ConnectionStatus[]) => void = () => {};
    invoke.mockImplementation((command: string) =>
      command === "status" ? new Promise((resolve) => (resolveStatus = resolve)) : Promise.resolve(null),
    );
    const refresh = store.refreshStatus();
    emit("daemon://event", { type: "credentials_required", profile_id: "p1", mode: "pin" });
    resolveStatus([]);
    await refresh;

    expect(store.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });
  });

  function line(seq: number): LogLine {
    return { seq, at_ms: seq, source: "daemon", text: `line ${seq}` };
  }

  it("re-fetches the log on a sequence gap", async () => {
    invoke.mockImplementation(async (command: string) =>
      command === "session_log" ? { profile_id: "p1", lines: [line(0), line(1), line(2), line(3)] } : null,
    );
    await store.refreshLog();
    expect(store.log.lines).toHaveLength(4);
    invoke.mockClear();

    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(4)] });
    expect(invoke).not.toHaveBeenCalledWith("session_log", undefined);

    invoke.mockImplementation(async (command: string) =>
      command === "session_log" ? { profile_id: "p1", lines: [0, 1, 2, 3, 4, 5, 6, 7].map(line) } : null,
    );
    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(7)] });
    expect(invoke).toHaveBeenCalledWith("session_log", undefined);
    await vi.waitFor(() => expect(store.log.stale).toBe(false));
    expect(store.log.lines.map((l) => l.seq)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it("keeps lines that arrive while the log is being fetched", async () => {
    let resolveLog: (log: { profile_id: string; lines: LogLine[] }) => void = () => {};
    invoke.mockImplementation((command: string) =>
      command === "session_log" ? new Promise((resolve) => (resolveLog = resolve)) : Promise.resolve(null),
    );
    const fetching = store.refreshLog();
    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(2), line(3)] });
    resolveLog({ profile_id: "p1", lines: [line(0), line(1), line(2)] });
    await fetching;

    expect(store.log.lines.map((l) => l.seq)).toEqual([0, 1, 2, 3]);
    expect(store.log.stale).toBe(false);
  });

  it("reports an older daemon that rejects the log request", async () => {
    invoke.mockRejectedValue({ code: "invalid_request", message: "unknown variant `session_log`" });
    await store.refreshLog();
    expect(store.logError?.code).toBe("invalid_request");
  });

  it("re-fetches on the next batch after a failed fetch and clears the error", async () => {
    invoke.mockImplementation(async (command: string) =>
      command === "session_log" ? { profile_id: "p1", lines: [0, 1, 2].map(line) } : null,
    );
    await store.refreshLog();
    invoke.mockRejectedValue({ code: "internal", message: "busy" });
    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(9)] });
    await vi.waitFor(() => expect(store.logError?.code).toBe("internal"));
    expect(store.log.stale).toBe(true);

    invoke.mockImplementation(async (command: string) =>
      command === "session_log" ? { profile_id: "p1", lines: [0, 1, 2, 3, 4, 5].map(line) } : null,
    );
    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(5)] });
    await vi.waitFor(() => expect(store.logError).toBeNull());
    expect(store.log).toEqual({ profileId: "p1", lines: [0, 1, 2, 3, 4, 5].map(line), stale: false });
  });

  it("keeps one log fetch in flight and retries only when a batch arrives", async () => {
    let rejectLog: (error: unknown) => void = () => {};
    invoke.mockImplementation((command: string) =>
      command === "session_log" ? new Promise((_, reject) => (rejectLog = reject)) : Promise.resolve(null),
    );
    const fetching = store.refreshLog();
    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(4)] });
    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(5)] });
    rejectLog({ code: "internal", message: "busy" });
    await fetching;

    const calls = () => invoke.mock.calls.filter(([command]) => command === "session_log").length;
    expect(calls()).toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(calls()).toBe(1);

    emit("daemon://event", { type: "log", profile_id: "p1", lines: [line(6)] });
    expect(calls()).toBe(2);
  });

  it("re-fetches when a batch belongs to a different profile than the held log", async () => {
    invoke.mockImplementation(async (command: string) =>
      command === "session_log" ? { profile_id: "p1", lines: [line(0), line(1)] } : null,
    );
    await store.refreshLog();
    invoke.mockClear();

    invoke.mockImplementation(async (command: string) =>
      command === "session_log" ? { profile_id: "p2", lines: [line(0), line(1)] } : null,
    );
    emit("daemon://event", { type: "log", profile_id: "p2", lines: [line(0)] });
    expect(invoke).toHaveBeenCalledWith("session_log", undefined);
    await vi.waitFor(() => expect(store.log.stale).toBe(false));
    expect(store.log).toEqual({ profileId: "p2", lines: [line(0), line(1)], stale: false });
  });

  it("shows a rename in the list without waiting for a reload", async () => {
    const renamed = { ...office, name: "Work", imported_name: "Office" };
    invoke.mockImplementation(async (command: string) => (command === "rename_profile" ? renamed : null));

    await store.rename("p1", "Work");

    expect(invoke).toHaveBeenCalledWith("rename_profile", { profileId: "p1", name: "Work" });
    expect(store.profiles).toEqual([renamed]);
  });
});
