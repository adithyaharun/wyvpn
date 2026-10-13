import { fireEvent, render, screen, within } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppInfo, NotificationPermission, ProfileSummary, Settings } from "$lib/types";

const invoke = vi.hoisted(() => vi.fn());
const copyText = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("$lib/clipboard", () => ({ copyText }));

import SettingsSheet from "./SettingsSheet.svelte";

function profile(id: string, name: string): ProfileSummary {
  return {
    id,
    name,
    server_name: "gw",
    server_host: "vpn.example.com",
    user: "alice",
    auth_mode: "pin",
    transports: ["open_vpn"],
  };
}

const profiles = [profile("p1", "Office"), profile("p2", "<b>Home</b>")];

let stored: Settings;
let launch: boolean;
let permission: NotificationPermission;
let info: AppInfo | Error;

function backend() {
  invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
    switch (command) {
      case "get_settings":
        return stored;
      case "update_settings":
        stored = args?.settings as Settings;
        return stored;
      case "get_launch_at_login":
        return launch;
      case "set_launch_at_login":
        launch = args?.enabled as boolean;
        return launch;
      case "notification_permission":
        return permission;
      case "app_info":
        if (info instanceof Error) throw "unknown command app_info";
        return info;
      default:
        return null;
    }
  });
}

type Overrides = Partial<{ onclose: () => void; onopenlog: () => void; logAvailable: boolean }>;

async function open(overrides: Overrides = {}) {
  render(SettingsSheet, { profiles, onclose: vi.fn(), onopenlog: vi.fn(), ...overrides });
  await vi.waitFor(() => expect(screen.getByRole("switch", { name: "Notifications" })).toBeEnabled());
  await vi.waitFor(() => expect(screen.getByRole("switch", { name: "Launch at login" })).toBeEnabled());
}

describe("SettingsSheet", () => {
  beforeEach(() => {
    invoke.mockReset();
    stored = { auto_connect_profile_id: null, auto_reconnect: true, notifications: true };
    launch = false;
    permission = "granted";
    info = { version: "0.1.0", os: "macOS", arch: "aarch64" };
    copyText.mockReset();
    copyText.mockResolvedValue(undefined);
    backend();
  });

  it("shows the stored settings", async () => {
    await open();
    expect(screen.getByRole("switch", { name: "Launch at login" })).not.toBeChecked();
    expect(screen.getByRole("switch", { name: "Reconnect automatically" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Notifications" })).toBeChecked();
    expect(screen.getByRole<HTMLSelectElement>("combobox", { name: "Default profile" }).value).toBe("");
  });

  it("saves launch at login through the OS", async () => {
    await open();
    await fireEvent.click(screen.getByRole("switch", { name: "Launch at login" }));
    expect(invoke).toHaveBeenCalledWith("set_launch_at_login", { enabled: true });
    await vi.waitFor(() => expect(screen.getByRole("switch", { name: "Launch at login" })).toBeChecked());
  });

  it("saves auto-reconnect", async () => {
    await open();
    await fireEvent.click(screen.getByRole("switch", { name: "Reconnect automatically" }));
    expect(invoke).toHaveBeenCalledWith("update_settings", {
      settings: { auto_connect_profile_id: null, auto_reconnect: false, notifications: true },
    });
    await vi.waitFor(() => expect(screen.getByRole("switch", { name: "Reconnect automatically" })).not.toBeChecked());
  });

  it("saves notifications and re-reads the permission", async () => {
    await open();
    invoke.mockClear();
    await fireEvent.click(screen.getByRole("switch", { name: "Notifications" }));
    expect(invoke).toHaveBeenCalledWith("update_settings", {
      settings: { auto_connect_profile_id: null, auto_reconnect: true, notifications: false },
    });
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("notification_permission", undefined));
  });

  it("saves the default profile", async () => {
    await open();
    const picker = screen.getByRole("combobox", { name: "Default profile" });
    await fireEvent.change(picker, { target: { value: "p2" } });
    expect(invoke).toHaveBeenCalledWith("update_settings", {
      settings: { auto_connect_profile_id: "p2", auto_reconnect: true, notifications: true },
    });

    await vi.waitFor(() => expect(picker).toBeEnabled());
    await fireEvent.change(picker, { target: { value: "" } });
    expect(invoke).toHaveBeenLastCalledWith("update_settings", {
      settings: { auto_connect_profile_id: null, auto_reconnect: true, notifications: true },
    });
  });

  it("lists None and every profile in the default profile picker", async () => {
    await open();
    const picker = screen.getByRole("combobox", { name: "Default profile" });
    const options = within(picker).getAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual(["None", "Office", "<b>Home</b>"]);
    expect(options.map((o) => (o as HTMLOptionElement).value)).toEqual(["", "p1", "p2"]);
    expect(picker.querySelector("b")).toBeNull();
  });

  it("selects the stored default profile", async () => {
    stored = { ...stored, auto_connect_profile_id: "p1" };
    await open();
    expect(screen.getByRole<HTMLSelectElement>("combobox", { name: "Default profile" }).value).toBe("p1");
  });

  it("points out a default profile that was removed", async () => {
    stored = { ...stored, auto_connect_profile_id: "gone" };
    await open();
    expect(screen.getByText("The default profile was removed. Choose another profile or None.")).toBeInTheDocument();
  });

  it("shows when the system blocks notifications", async () => {
    permission = "denied";
    await open();
    await vi.waitFor(() =>
      expect(screen.getByText(/Your system blocks notifications from WyVPN/)).toBeInTheDocument(),
    );
  });

  it("does not show the blocked state when notifications are allowed", async () => {
    await open();
    expect(screen.queryByText(/blocks notifications/)).toBeNull();
  });

  it("mentions that development builds register the development binary", async () => {
    await open();
    expect(screen.getByText(/Development builds register the development binary/)).toBeInTheDocument();
  });

  it("restores the toggle and explains when saving fails", async () => {
    await open();
    invoke.mockImplementation(async (command: string) => {
      if (command === "update_settings") throw { code: "io", message: "disk full" };
      return null;
    });
    await fireEvent.click(screen.getByRole("switch", { name: "Reconnect automatically" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Reconnect automatically" })).toBeChecked();
  });

  describe("support", () => {
    it("shows the app version and platform", async () => {
      await open();
      expect(await screen.findByText("WyVPN 0.1.0")).toBeInTheDocument();
      expect(screen.getByText("macOS aarch64")).toBeInTheDocument();
    });

    it("copies the version with the platform", async () => {
      await open();
      await fireEvent.click(await screen.findByRole("button", { name: "Copy version" }));
      expect(copyText).toHaveBeenCalledWith("WyVPN 0.1.0 (macOS aarch64)");
    });

    it("hides the version when the backend can't report it", async () => {
      info = new Error("old backend");
      await open();
      await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("app_info", undefined));
      expect(screen.queryByText(/^WyVPN \d/)).toBeNull();
      expect(screen.queryByRole("button", { name: "Copy version" })).toBeNull();
      expect(screen.getByRole("button", { name: "GitHub project" })).toBeInTheDocument();
      expect(screen.queryByRole("alert")).toBeNull();
    });

    it("opens the project and issue pages through the backend", async () => {
      await open();
      await fireEvent.click(screen.getByRole("button", { name: "GitHub project" }));
      expect(invoke).toHaveBeenCalledWith("open_support", { target: "project" });
      await fireEvent.click(screen.getByRole("button", { name: "Report an issue" }));
      expect(invoke).toHaveBeenCalledWith("open_support", { target: "issue" });
    });

    it("explains when the browser can't be opened", async () => {
      await open();
      invoke.mockImplementation(async (command: string) => {
        if (command === "open_support") throw { code: "io", message: "no browser" };
        return null;
      });
      await fireEvent.click(screen.getByRole("button", { name: "Report an issue" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("WyVPN couldn't open your browser. Try again.");
    });

    it("opens the connection log", async () => {
      const onopenlog = vi.fn();
      await open({ onopenlog });
      await fireEvent.click(screen.getByRole("button", { name: "Connection log" }));
      expect(onopenlog).toHaveBeenCalledOnce();
    });

    it("disables the connection log while the service is unavailable", async () => {
      await open({ logAvailable: false });
      expect(screen.getByRole("button", { name: "Connection log" })).toBeDisabled();
    });
  });
});
