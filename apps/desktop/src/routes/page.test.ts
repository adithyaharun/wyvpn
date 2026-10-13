import { fireEvent, render, screen, within } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { StartupNotice } from "$lib/types";

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
        return { auto_connect_profile_id: "gone", auto_reconnect: false, notifications: false };
      case "get_launch_at_login":
        return false;
      case "notification_permission":
        return "granted";
      case "session_log":
        return { profile_id: null, lines: [] };
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
