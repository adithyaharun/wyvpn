import { fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

import DaemonSetup from "./DaemonSetup.svelte";

describe("DaemonSetup", () => {
  beforeEach(() => {
    invoke.mockReset();
    vi.useFakeTimers();
  });

  afterEach(() => vi.useRealTimers());

  it("registers an unregistered service on its own", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "service_status") return "not_registered";
      if (command === "register_service") return "requires_approval";
      return null;
    });
    render(DaemonSetup, { setup: "not_registered" });

    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("register_service", undefined));
    expect(await screen.findByRole("button", { name: "Open System Settings" })).toBeInTheDocument();
  });

  it("polls every two seconds and continues once the service is enabled", async () => {
    let status = "requires_approval";
    invoke.mockImplementation(async (command: string) => {
      if (command === "service_status") return status;
      if (command === "daemon_state") return { available: false, socket: "/s", status: "unreachable" };
      return null;
    });
    render(DaemonSetup, { setup: "requires_approval" });
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("service_status", undefined));
    expect(invoke).not.toHaveBeenCalledWith("daemon_state", undefined);

    status = "enabled";
    await vi.advanceTimersByTimeAsync(2000);

    expect(await screen.findByText("Approved. Starting the service…")).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("daemon_state", undefined);
    expect(invoke).not.toHaveBeenCalledWith("register_service", undefined);
  });

  it("explains the one-time approval and opens Login Items", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "service_status") return "requires_approval";
      return null;
    });
    render(DaemonSetup, { setup: "requires_approval" });

    expect(screen.getByText(/macOS asks only once/)).toHaveTextContent("runs for all users of this Mac");
    expect(screen.getByText(/If you dismissed the macOS prompt/)).toHaveTextContent(
      "Allow in the Background in System Settings",
    );
    await fireEvent.click(screen.getByRole("button", { name: "Open System Settings" }));
    expect(invoke).toHaveBeenCalledWith("open_login_items", undefined);
    expect(invoke).not.toHaveBeenCalledWith("register_service", undefined);
  });

  it("shows a registration error and stops retrying on its own", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "service_status") return "not_found";
      if (command === "register_service") throw { code: "service_setup", message: "Operation not permitted" };
      return null;
    });
    render(DaemonSetup, { setup: "not_found" });

    expect(await screen.findByRole("alert")).toHaveTextContent("Operation not permitted");
    await vi.advanceTimersByTimeAsync(6000);
    expect(invoke.mock.calls.filter(([command]) => command === "register_service")).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});
