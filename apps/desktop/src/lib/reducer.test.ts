import { describe, expect, it } from "vitest";
import { activeSession, applyEvent, initialState, LOG_CAPACITY, type DaemonState } from "./reducer";
import type { ConnectionStatus, LogLine, ProfileSummary } from "./types";

const profile: ProfileSummary = {
  id: "p1",
  name: "Office",
  server_name: "gw",
  server_host: "vpn.example.com",
  user: "alice",
  auth_mode: "pin",
  transports: ["wire_guard"],
};

const connected: ConnectionStatus = {
  profile_id: "p1",
  profile_name: "Office",
  state: "connected",
  transport: "wire_guard",
  tunnel_ip: "10.0.0.2",
  server_endpoint: "vpn.example.com:51820",
  connected_since: 1_700_000_000,
  rx_bytes: 10,
  tx_bytes: 20,
};

function withData(): DaemonState {
  let state = applyEvent(initialState(), { type: "availability", available: true, socket: "/tmp/w.sock" });
  state = applyEvent(state, { type: "profiles", profiles: [profile] });
  return applyEvent(state, { type: "statuses", statuses: [connected] });
}

describe("applyEvent", () => {
  it("tracks availability and drops pending credentials when the daemon goes away", () => {
    let state = applyEvent(initialState(), { type: "availability", available: true, socket: "/run/w.sock" });
    expect(state.available).toBe(true);
    expect(state.socket).toBe("/run/w.sock");

    state = applyEvent(state, { type: "credentials_required", profile_id: "p1", mode: "pin" });
    state = applyEvent(state, { type: "availability", available: false, socket: "/run/w.sock" });
    expect(state.available).toBe(false);
    expect(state.pendingCredentials).toBeNull();
  });

  it("keeps the starting status while the service is unreachable", () => {
    const state = applyEvent(initialState(), {
      type: "availability",
      available: false,
      socket: "/run/w.sock",
      status: "starting",
    });
    expect(state.available).toBe(false);
    expect(state.status).toBe("starting");
  });

  it("applies state_changed to an existing status", () => {
    const state = applyEvent(withData(), {
      type: "state_changed",
      profile_id: "p1",
      state: "error",
      error: { code: "auth_failed", message: "rejected" },
    });
    expect(state.statuses.p1.state).toBe("error");
    expect(state.statuses.p1.error).toEqual({ code: "auth_failed", message: "rejected" });
    expect(state.statuses.p1.connected_since).toBeNull();
  });

  it("creates a status for an unknown session using the profile name", () => {
    let state = applyEvent(initialState(), { type: "profiles", profiles: [profile] });
    state = applyEvent(state, { type: "state_changed", profile_id: "p1", state: "connecting" });
    expect(state.statuses.p1).toMatchObject({ state: "connecting", profile_name: "Office", error: null });
    expect(activeSession(state)?.profile_id).toBe("p1");
  });

  it("clears an old error once the session moves on", () => {
    let state = applyEvent(withData(), {
      type: "state_changed",
      profile_id: "p1",
      state: "error",
      error: { code: "timeout", message: "slow" },
    });
    state = applyEvent(state, { type: "state_changed", profile_id: "p1", state: "connecting" });
    expect(state.statuses.p1.error).toBeNull();
  });

  it("opens and resolves credential requests", () => {
    let state = applyEvent(withData(), { type: "credentials_required", profile_id: "p1", mode: "pin" });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });

    state = applyEvent(state, { type: "state_changed", profile_id: "p1", state: "connecting" });
    expect(state.pendingCredentials).not.toBeNull();

    state = applyEvent(state, { type: "state_changed", profile_id: "p1", state: "disconnected" });
    expect(state.pendingCredentials).toBeNull();
  });

  it("keeps the requested mode for unsupported sign-in methods", () => {
    const state = applyEvent(initialState(), { type: "credentials_required", profile_id: "p1", mode: "otp" });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "otp" });
  });

  it("clears pending credentials locally for the matching profile only", () => {
    let state = applyEvent(withData(), { type: "credentials_required", profile_id: "p1", mode: "pin" });
    state = applyEvent(state, { type: "credentials_cleared", profile_id: "other" });
    expect(state.pendingCredentials).not.toBeNull();
    state = applyEvent(state, { type: "credentials_cleared", profile_id: "p1" });
    expect(state.pendingCredentials).toBeNull();
  });

  it("applies stats to a known session and ignores unknown ones", () => {
    const before = withData();
    const after = applyEvent(before, { type: "stats", profile_id: "p1", rx_bytes: 4096, tx_bytes: 512 });
    expect(after.statuses.p1).toMatchObject({ rx_bytes: 4096, tx_bytes: 512, tunnel_ip: "10.0.0.2" });
    expect(before.statuses.p1.rx_bytes).toBe(10);

    const ignored = applyEvent(before, { type: "stats", profile_id: "nope", rx_bytes: 1, tx_bytes: 1 });
    expect(ignored).toBe(before);
  });

  it("drops a pending request when its profile disappears", () => {
    let state = applyEvent(withData(), { type: "credentials_required", profile_id: "p1", mode: "pin" });
    state = applyEvent(state, { type: "profiles", profiles: [] });
    expect(state.pendingCredentials).toBeNull();
  });

  it("replaces statuses from a heartbeat so a missed state change heals", () => {
    let state = applyEvent(withData(), { type: "state_changed", profile_id: "p1", state: "disconnecting" });
    state = applyEvent(state, { type: "statuses", statuses: [{ ...connected, state: "disconnected", tunnel_ip: null }] });
    expect(state.statuses.p1).toMatchObject({ state: "disconnected", tunnel_ip: null });

    state = applyEvent(state, { type: "statuses", statuses: [] });
    expect(state.statuses).toEqual({});
    expect(activeSession(state)).toBeNull();
  });

  it("shows the latest session, not an older profile's error", () => {
    let state = applyEvent(initialState(), {
      type: "statuses",
      statuses: [
        { ...connected, profile_id: "a", state: "error", tunnel_ip: null, error: { code: "auth_failed", message: "bad pin" } },
        { ...connected, profile_id: "b", state: "disconnected", tunnel_ip: null },
      ],
    });
    expect(activeSession(state)?.profile_id).toBe("a");

    state = applyEvent(state, { type: "state_changed", profile_id: "b", state: "connecting" });
    state = applyEvent(state, { type: "state_changed", profile_id: "b", state: "connected" });
    expect(activeSession(state)?.profile_id).toBe("b");

    state = applyEvent(state, { type: "state_changed", profile_id: "b", state: "disconnected" });
    expect(activeSession(state)).toBeNull();
  });

  it("replaces the profile list from a profiles event", () => {
    const home: ProfileSummary = { ...profile, id: "p2", name: "Home" };
    let state = applyEvent(withData(), { type: "profiles", profiles: [profile, home] });
    expect(state.profiles.map((p) => p.name)).toEqual(["Office", "Home"]);

    state = applyEvent(state, { type: "profiles", profiles: [home] });
    expect(state.profiles.map((p) => p.id)).toEqual(["p2"]);
  });
});

describe("awaiting credentials", () => {
  const awaiting: ConnectionStatus = { ...connected, state: "connecting", connected_since: null, awaiting: "pin" };
  const connecting: ConnectionStatus = { ...awaiting, awaiting: undefined };

  it("restores a missed prompt from a status", () => {
    const state = applyEvent(withData(), { type: "statuses", statuses: [awaiting] });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });
  });

  it("keeps the prompt while connecting and clears it once the session moves on", () => {
    let state = applyEvent(withData(), { type: "credentials_required", profile_id: "p1", mode: "pin" });
    state = applyEvent(state, { type: "statuses", statuses: [connecting] });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });

    state = applyEvent(state, { type: "statuses", statuses: [{ ...connecting, state: "error" }] });
    expect(state.pendingCredentials).toBeNull();
  });

  it("clears the prompt when its session is gone", () => {
    let state = applyEvent(withData(), { type: "statuses", statuses: [awaiting] });
    state = applyEvent(state, { type: "statuses", statuses: [] });
    expect(state.pendingCredentials).toBeNull();
  });

  it("ignores a stale awaiting status after the prompt is resolved locally", () => {
    let state = applyEvent(withData(), { type: "statuses", statuses: [awaiting] });
    state = applyEvent(state, { type: "credentials_cleared", profile_id: "p1" });
    expect(state.pendingCredentials).toBeNull();

    state = applyEvent(state, { type: "statuses", statuses: [awaiting] });
    expect(state.pendingCredentials).toBeNull();

    state = applyEvent(state, { type: "statuses", statuses: [connecting] });
    state = applyEvent(state, { type: "statuses", statuses: [awaiting] });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });
  });

  it("re-opens immediately when the daemon asks again", () => {
    let state = applyEvent(withData(), { type: "statuses", statuses: [awaiting] });
    state = applyEvent(state, { type: "credentials_cleared", profile_id: "p1" });
    state = applyEvent(state, { type: "credentials_required", profile_id: "p1", mode: "pin" });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });

    state = applyEvent(state, { type: "statuses", statuses: [awaiting] });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });
  });

  it("forgets suppressed prompts when the daemon goes away", () => {
    let state = applyEvent(withData(), { type: "credentials_cleared", profile_id: "p1" });
    state = applyEvent(state, { type: "availability", available: false, socket: "" });
    state = applyEvent(state, { type: "availability", available: true, socket: "" });
    state = applyEvent(state, { type: "statuses", statuses: [awaiting] });
    expect(state.pendingCredentials).toEqual({ profileId: "p1", mode: "pin" });
  });
});

describe("profile changes", () => {
  it("leaves state untouched on profiles_changed until the new list arrives", () => {
    const before = withData();
    const after = applyEvent(before, { type: "profiles_changed" });
    expect(after).toBe(before);

    const renamed = { ...profile, name: "Work", imported_name: "Office" };
    const listed = applyEvent(after, { type: "profiles", profiles: [renamed] });
    expect(listed.profiles[0]).toMatchObject({ name: "Work", imported_name: "Office" });
  });

  it("applies a renamed profile to the list and the active status", () => {
    const renamed = { ...profile, name: "Work", imported_name: "Office" };
    const state = applyEvent(withData(), { type: "profile_updated", profile: renamed });
    expect(state.profiles).toEqual([renamed]);
    expect(state.statuses.p1.profile_name).toBe("Work");
  });

  it("ignores an update for a profile that is no longer listed", () => {
    const before = withData();
    expect(applyEvent(before, { type: "profile_updated", profile: { ...profile, id: "gone" } })).toBe(before);
  });
});

describe("session log", () => {
  function line(seq: number, text = `line ${seq}`): LogLine {
    return { seq, at_ms: 1_700_000_000_000 + seq, source: "tunnel", text };
  }

  function loaded(lines: LogLine[]): DaemonState {
    return applyEvent(withData(), { type: "log_loaded", profile_id: "p1", lines });
  }

  it("starts stale so the first batch triggers a fetch", () => {
    expect(initialState().log).toEqual({ profileId: null, lines: [], stale: true });
  });

  it("replaces the buffer from a fetch", () => {
    const state = loaded([line(0), line(1)]);
    expect(state.log).toEqual({ profileId: "p1", lines: [line(0), line(1)], stale: false });
  });

  it("appends contiguous lines", () => {
    const state = applyEvent(loaded([line(0), line(1)]), { type: "log", profile_id: "p1", lines: [line(2), line(3)] });
    expect(state.log.lines.map((l) => l.seq)).toEqual([0, 1, 2, 3]);
    expect(state.log.stale).toBe(false);
  });

  it("marks a sequence gap as stale and keeps the lines", () => {
    const state = applyEvent(loaded([line(0), line(1)]), { type: "log", profile_id: "p1", lines: [line(5)] });
    expect(state.log.stale).toBe(true);
    expect(state.log.lines.map((l) => l.seq)).toEqual([0, 1, 5]);
  });

  it("drops lines it already holds", () => {
    const state = applyEvent(loaded([line(0), line(1), line(2)]), {
      type: "log",
      profile_id: "p1",
      lines: [line(1), line(2), line(3)],
    });
    expect(state.log.lines.map((l) => l.seq)).toEqual([0, 1, 2, 3]);
    expect(state.log.stale).toBe(false);
  });

  it("starts over when a new session restarts the sequence", () => {
    const state = applyEvent(loaded([line(0, "old"), line(1, "old")]), {
      type: "log",
      profile_id: "p1",
      lines: [line(0, "new")],
    });
    expect(state.log).toEqual({ profileId: "p1", lines: [line(0, "new")], stale: false });
  });

  it("marks a batch from another profile that misses its start as stale", () => {
    const state = applyEvent(loaded([line(0)]), { type: "log", profile_id: "p2", lines: [line(4)] });
    expect(state.log).toMatchObject({ profileId: "p2", stale: true });
    expect(state.log.lines).toEqual([line(4)]);
  });

  it("treats a batch from another profile as a new session that needs a fetch", () => {
    const state = applyEvent(loaded([line(0), line(1)]), { type: "log", profile_id: "p2", lines: [line(0)] });
    expect(state.log).toEqual({ profileId: "p2", lines: [line(0)], stale: true });
  });

  it("takes a session start as complete when no log is held yet", () => {
    const state = applyEvent(withData(), { type: "log", profile_id: "p1", lines: [line(0), line(1)] });
    expect(state.log).toEqual({ profileId: "p1", lines: [line(0), line(1)], stale: false });
  });

  it("stays stale after a gap until a fetch or a session start replaces the buffer", () => {
    let state = applyEvent(loaded([line(0), line(1)]), { type: "log", profile_id: "p1", lines: [line(15)] });
    state = applyEvent(state, { type: "log", profile_id: "p1", lines: [line(16)] });
    expect(state.log.stale).toBe(true);

    state = applyEvent(state, { type: "log", profile_id: "p1", lines: [line(0, "new")] });
    expect(state.log).toEqual({ profileId: "p1", lines: [line(0, "new")], stale: false });
  });

  it("keeps at most the daemon's capacity", () => {
    const many = Array.from({ length: LOG_CAPACITY }, (_, i) => line(i));
    const state = applyEvent(loaded(many), { type: "log", profile_id: "p1", lines: [line(LOG_CAPACITY)] });
    expect(state.log.lines).toHaveLength(LOG_CAPACITY);
    expect(state.log.lines[0].seq).toBe(1);
    expect(state.log.lines.at(-1)?.seq).toBe(LOG_CAPACITY);
  });
});
