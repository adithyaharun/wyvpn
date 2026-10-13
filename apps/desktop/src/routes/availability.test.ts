import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DaemonAvailability } from "$lib/types";

const invoke = vi.hoisted(() => vi.fn());
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return () => handlers.delete(name);
  }),
}));

import { daemon } from "$lib/daemon.svelte";
import Page from "./+page.svelte";

function backend(availability: DaemonAvailability, service: string | null = null) {
  invoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "daemon_state":
        return availability;
      case "list_profiles":
      case "status":
        return [];
      case "service_status":
        return service;
      case "get_settings":
        return { auto_connect_profile_id: null, auto_reconnect: false, notifications: false };
      case "get_launch_at_login":
        return false;
      case "notification_permission":
        return "granted";
      case "app_info":
        return { version: "0.1.0", os: "Linux", arch: "x86_64" };
      case "third_party_licenses":
        return "MIT License text";
      case "openvpn_notice":
        return { license: "GPL-2.0", source_url: null };
      default:
        return null;
    }
  });
}

describe("daemon availability screens", () => {
  beforeEach(() => {
    handlers.clear();
    invoke.mockReset();
    daemon.dispatch({ type: "availability", available: false, socket: "" });
  });

  it("names both versions when the service is incompatible", async () => {
    backend({
      available: false,
      socket: "/s",
      status: "incompatible",
      mismatch: { client_version: "0.2.0", client_protocol: 2, daemon_version: "0.1.0", daemon_protocol: 1 },
    });
    render(Page);

    expect(await screen.findByText("Update WyVPN or restart the service")).toBeInTheDocument();
    expect(await screen.findByText("0.2.0 (protocol 2)")).toBeInTheDocument();
    expect(await screen.findByText("0.1.0 (protocol 1)")).toBeInTheDocument();
  });

  it("treats an older service without a version as incompatible", async () => {
    backend({
      available: false,
      socket: "/s",
      status: "incompatible",
      mismatch: { client_version: "0.2.0", client_protocol: 2, daemon_version: null, daemon_protocol: null },
    });
    render(Page);

    expect(await screen.findByText("Update WyVPN or restart the service")).toBeInTheDocument();
    expect(await screen.findByText("an older version")).toBeInTheDocument();
  });

  it("explains how to join the wyvpn group when not permitted", async () => {
    backend({ available: false, socket: "/s", status: "not_permitted" });
    render(Page);

    expect(await screen.findByText("Join the wyvpn group")).toBeInTheDocument();
    expect(screen.getByText("sudo usermod -aG wyvpn $USER")).toBeInTheDocument();
    expect(screen.getByText(/log out and back in/i)).toBeInTheDocument();
  });

  it("shows the approval step with a System Settings button", async () => {
    backend({ available: false, socket: "/s", status: "needs_setup", setup: "requires_approval" }, "requires_approval");
    render(Page);

    await fireEvent.click(await screen.findByRole("button", { name: "Open System Settings" }));
    expect(invoke).toHaveBeenCalledWith("open_login_items", undefined);
    expect(invoke).not.toHaveBeenCalledWith("register_service", undefined);
  });

  it("keeps the plain unavailable screen for an unreachable service", async () => {
    backend({ available: false, socket: "/s" });
    render(Page);

    expect(await screen.findByText("WyVPN service isn't running")).toBeInTheDocument();
  });

  it("shows the starting screen while an approved service comes up", async () => {
    backend({ available: false, socket: "/s", status: "starting" });
    render(Page);

    expect(await screen.findByText("Starting the WyVPN service…")).toBeInTheDocument();
    expect(screen.queryByText("WyVPN service isn't running")).not.toBeInTheDocument();
  });

  it("switches screens when an availability event arrives", async () => {
    backend({ available: false, socket: "/s" });
    render(Page);
    await screen.findByText("WyVPN service isn't running");
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("daemon_state", undefined));
    await new Promise((resolve) => setTimeout(resolve, 20));

    handlers.get("daemon://availability")?.({ payload: { available: false, socket: "/s", status: "not_permitted" } });
    expect(await screen.findByText("Join the wyvpn group")).toBeInTheDocument();
  });

  it("opens the licenses view from Settings", async () => {
    backend({ available: true, socket: "/s", status: "available" });
    render(Page);

    await fireEvent.click(await screen.findByRole("button", { name: /settings/i }));
    await fireEvent.click(await screen.findByRole("button", { name: /third-party licenses/i }));
    expect(await screen.findByText("MIT License text")).toBeInTheDocument();
    expect(screen.getByText(/uses your distribution's OpenVPN package/)).toBeInTheDocument();
  });

  it("opens the licenses view from the menu event", async () => {
    backend({ available: true, socket: "/s", status: "available" });
    render(Page);
    await vi.waitFor(() => expect(handlers.has("app://open-licenses")).toBe(true));

    handlers.get("app://open-licenses")?.({ payload: null });
    expect(await screen.findByText("MIT License text")).toBeInTheDocument();
  });
});
