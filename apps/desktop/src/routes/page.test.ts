import { fireEvent, render, screen, within } from "@testing-library/svelte";
import { tick } from "svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionStatus, StartupNotice, UpdateState, WindowRequest } from "$lib/types";
import { updates } from "$lib/update.svelte";

const invoke = vi.hoisted(() => vi.fn());
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return () => handlers.delete(name);
  }),
}));

import Page from "./+page.svelte";

let windowRequests: WindowRequest[] = [];

function emit(name: string, payload: unknown = null) {
  const handler = handlers.get(name);
  if (!handler) throw new Error(`no listener for ${name}`);
  handler({ payload });
}

function wake(name: string, ...requests: WindowRequest[]) {
  windowRequests.push(...requests);
  emit(name);
}

function drains() {
  return invoke.mock.calls.filter(([command]) => command === "take_window_requests").length;
}

async function drained(count: number) {
  await vi.waitFor(() => expect(drains()).toBe(count));
  const last = invoke.mock.calls.map(([command]) => command).lastIndexOf("take_window_requests");
  await invoke.mock.results[last]?.value;
  await new Promise((resolve) => setTimeout(resolve));
  await tick();
}

beforeEach(() => {
  windowRequests = [];
});

const message = "Your default profile was removed, so WyVPN didn't connect automatically. Choose another in Settings.";

function backend(stored: StartupNotice | null, available = true) {
  invoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "daemon_state":
        return { available, socket: "/tmp/w.sock" };
      case "list_profiles":
      case "status":
        return [];
      case "take_startup_notice":
        return stored;
      case "get_settings":
        return { auto_connect_profile_id: "gone", auto_reconnect: false, notifications: false, check_updates: true };
      case "get_launch_at_login":
        return false;
      case "notification_permission":
        return "granted";
      case "session_log":
        return { profile_id: null, lines: [] };
      case "take_window_requests":
        return windowRequests.splice(0);
      case "third_party_licenses":
        return "MIT License text";
      case "openvpn_notice":
        return { license: "GPL-2.0", source_url: null };
      default:
        return null;
    }
  });
}

describe("default profile notice", () => {
  beforeEach(() => {
    handlers.clear();
    invoke.mockReset();
  });

  it("shows a notice stored before the window loaded", async () => {
    backend({ profile_id: "gone" });
    render(Page);

    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("take_startup_notice", undefined);
  });

  it("shows the notice when the event arrives and can be dismissed", async () => {
    backend(null);
    render(Page);
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("take_startup_notice", undefined));
    expect(screen.queryByText(message)).toBeNull();

    handlers.get("app://default-profile-missing")?.({ payload: { profile_id: "gone" } });
    expect(await screen.findByText(message)).toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText(message)).toBeNull();
  });

  it("opens Settings from the notice", async () => {
    backend({ profile_id: "gone" });
    render(Page);

    await fireEvent.click(await screen.findByRole("button", { name: "Open Settings" }));

    expect(screen.getByRole("dialog", { name: "Settings" })).toBeInTheDocument();
    expect(screen.queryByText(message)).toBeNull();
  });

  it("stays hidden when the backend has no notice command", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "take_startup_notice") throw "unknown command take_startup_notice";
      if (command === "daemon_state") return { available: true, socket: "/tmp/w.sock" };
      return command === "list_profiles" || command === "status" ? [] : null;
    });
    render(Page);

    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("take_startup_notice", undefined));
    expect(screen.queryByText(message)).toBeNull();
  });
});

describe("toolbar", () => {
  beforeEach(() => {
    handlers.clear();
    invoke.mockReset();
  });

  it("opens the log, settings and import sheets", async () => {
    backend(null);
    render(Page);
    const log = screen.getByRole("button", { name: "Connection log" });
    await vi.waitFor(() => expect(log).toBeEnabled());

    await fireEvent.click(log);
    expect(screen.getByRole("dialog", { name: "Connection log" })).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Close" }));

    await fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(screen.getByRole("dialog", { name: "Settings" })).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Close" }));

    await fireEvent.click(screen.getByTitle("Import profile"));
    expect(screen.getByRole("dialog", { name: "Import profile" })).toBeInTheDocument();
  });

  it("opens the log from Settings", async () => {
    backend(null);
    render(Page);
    await vi.waitFor(() => expect(screen.getByRole("button", { name: "Connection log" })).toBeEnabled());

    await fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    const settings = screen.getByRole("dialog", { name: "Settings" });
    await fireEvent.click(within(settings).getByRole("button", { name: "Connection log" }));

    expect(screen.getByRole("dialog", { name: "Connection log" })).toBeInTheDocument();
    await vi.waitFor(() => expect(screen.queryByRole("dialog", { name: "Settings" })).toBeNull());
  });

  it("disables the connection log while the service is unavailable", async () => {
    backend(null, false);
    render(Page);
    expect(await screen.findByText("WyVPN service isn't running")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Connection log" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Settings" })).toBeEnabled();
  });

  it("replaces the bottom bar", () => {
    backend(null);
    render(Page);
    expect(screen.queryByRole("navigation")).toBeNull();
    expect(screen.getAllByRole("button", { name: "Connection log" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Settings" })).toHaveLength(1);
  });
});

describe("window requests", () => {
  const licenses = { name: "Third-party licenses" };

  beforeEach(() => {
    handlers.clear();
    invoke.mockReset();
  });

  it("opens the licenses panel for a request queued before mount", async () => {
    backend(null);
    windowRequests.push({ kind: "licenses" });
    render(Page);

    expect(await screen.findByRole("dialog", licenses)).toBeInTheDocument();
    expect(windowRequests).toEqual([]);
  });

  it("opens no panel when the queue is empty at mount", async () => {
    backend(null);
    render(Page);

    await drained(1);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("drains the queue and opens the licenses panel on the menu event", async () => {
    backend(null);
    render(Page);
    await drained(1);

    wake("app://open-licenses", { kind: "licenses" });

    expect(await screen.findByRole("dialog", licenses)).toBeInTheDocument();
    expect(drains()).toBe(2);
  });

  it("ignores the menu event when the queue is empty", async () => {
    backend(null);
    render(Page);
    await drained(1);

    emit("app://open-licenses");

    await drained(2);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("updates", () => {
  const offer: UpdateState = {
    state: "available",
    version: "0.3.0",
    notes: "Fixes",
    date: null,
    installable: true,
    release_url: "https://github.com/adithyaharun/wyvpn/releases/tag/v0.3.0",
  };

  const connected: ConnectionStatus = {
    profile_id: "p1",
    profile_name: "Office",
    state: "connected",
    transport: "open_vpn",
    tunnel_ip: "10.0.0.2",
    server_endpoint: "vpn.example.com:443",
    connected_since: 1,
    rx_bytes: 0,
    tx_bytes: 0,
  };

  function updateBackend(state: UpdateState, statuses: ConnectionStatus[] = []) {
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case "daemon_state":
          return { available: true, socket: "/tmp/w.sock" };
        case "list_profiles":
          return [];
        case "status":
          return statuses;
        case "update_state":
          return state;
        case "dismiss_update":
          return { ...offer, state: "dismissed" };
        case "take_window_requests":
          return windowRequests.splice(0);
        default:
          return null;
      }
    });
  }

  async function ready() {
    render(Page);
    await vi.waitFor(() => expect(handlers.has("app://update-prompt")).toBe(true));
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("update_state", undefined));
  }

  beforeEach(() => {
    handlers.clear();
    invoke.mockReset();
    updates.state = { state: "idle" };
    updates.open = false;
    updates.error = null;
  });

  it("opens the update sheet for an available prompt", async () => {
    updateBackend({ ...offer, version: "0.2.9", state: "dismissed" });
    await ready();
    expect(screen.queryByRole("dialog", { name: "Software update" })).toBeNull();

    wake("app://update-prompt", { kind: "update_prompt", outcome: "available" });
    expect(await screen.findByRole("dialog", { name: "Software update" })).toBeInTheDocument();
    expect(screen.getByText("WyVPN 0.2.9 is available")).toBeInTheDocument();
  });

  it("drains the queue and opens the update prompt on the prompt event", async () => {
    updateBackend({ ...offer, version: "0.2.9", state: "dismissed" });
    await ready();

    wake("app://update-prompt", { kind: "update_prompt", outcome: "available" });

    expect(await screen.findByRole("dialog", { name: "Software update" })).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("take_window_requests", undefined);
    expect(windowRequests).toEqual([]);
  });

  it("opens the update prompt for a request queued before mount", async () => {
    updateBackend({ ...offer, version: "0.2.9", state: "dismissed" });
    windowRequests.push({ kind: "update_prompt", outcome: "available" });
    render(Page);

    expect(await screen.findByRole("dialog", { name: "Software update" })).toBeInTheDocument();
    expect(screen.getByText("WyVPN 0.2.9 is available")).toBeInTheDocument();
  });

  it("ignores the prompt event payload when the queue is empty", async () => {
    updateBackend({ ...offer, version: "0.2.9", state: "dismissed" });
    await ready();
    await drained(1);

    emit("app://update-prompt", { outcome: "available" });

    await drained(2);
    expect(screen.queryByRole("dialog", { name: "Software update" })).toBeNull();
  });

  it("shows that WyVPN is up to date after a menu check", async () => {
    updateBackend({ state: "idle" });
    await ready();
    emit("app://update", { state: "up_to_date" });
    wake("app://update-prompt", { kind: "update_prompt", outcome: "up_to_date" });
    expect(await screen.findByText("WyVPN is up to date")).toBeInTheDocument();
  });

  it("shows the error after a failed menu check", async () => {
    updateBackend({ state: "idle" });
    await ready();
    emit("app://update", { state: "failed", message: "Could not reach the update server." });
    wake("app://update-prompt", { kind: "update_prompt", outcome: "failed" });
    const dialog = await screen.findByRole("dialog", { name: "Software update" });
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Could not reach the update server.");
    expect(within(dialog).getByRole("button", { name: "Check again" })).toBeInTheDocument();
  });

  it("opens for an update found while the window was hidden and Later closes it", async () => {
    updateBackend(offer);
    await ready();
    const dialog = await screen.findByRole("dialog", { name: "Software update" });
    expect(within(dialog).queryByRole("note")).toBeNull();

    await fireEvent.click(within(dialog).getByRole("button", { name: "Later" }));
    expect(invoke).toHaveBeenCalledWith("dismiss_update", undefined);
    await vi.waitFor(() => expect(screen.queryByRole("dialog", { name: "Software update" })).toBeNull());
  });

  it("keeps focus in the sheet during an install and returns it on close", async () => {
    updateBackend({ ...offer, version: "0.2.9", state: "dismissed" });
    await ready();
    const trigger = screen.getByRole("button", { name: "Settings" });
    trigger.focus();

    wake("app://update-prompt", { kind: "update_prompt", outcome: "available" });
    const dialog = await screen.findByRole("dialog", { name: "Software update" });
    const install = within(dialog).getByRole("button", { name: "Install" });
    install.focus();
    await fireEvent.click(install);
    expect(invoke).toHaveBeenCalledWith("install_update", undefined);
    emit("app://update", { state: "disconnecting", version: "0.3.0" });
    await vi.waitFor(() => expect(document.activeElement).toBe(within(dialog).getByRole("status")));

    emit("app://update", { state: "failed", message: "The update could not be downloaded. Nothing was installed." });
    await within(dialog).findByRole("button", { name: "Check again" });
    const close = within(dialog).getByRole("button", { name: "Close" });
    expect(close).toBeEnabled();
    await fireEvent.click(close);
    await vi.waitFor(() => expect(screen.queryByRole("dialog", { name: "Software update" })).toBeNull());
    expect(document.activeElement).toBe(trigger);
  });

  it("warns about the active VPN session", async () => {
    updateBackend({ ...offer, version: "0.3.1" }, [connected]);
    await ready();
    const dialog = await screen.findByRole("dialog", { name: "Software update" });
    await vi.waitFor(() =>
      expect(within(dialog).getByRole("note")).toHaveTextContent("Installing disconnects the VPN."),
    );
  });
});
