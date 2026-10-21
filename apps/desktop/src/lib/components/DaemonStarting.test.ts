import { fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

import DaemonStarting from "./DaemonStarting.svelte";

describe("DaemonStarting", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
    vi.useFakeTimers();
  });

  afterEach(() => vi.useRealTimers());

  it("shows the starting state without the not-running text", () => {
    render(DaemonStarting, { socket: "/var/run/wyvpn.sock" });

    expect(screen.getByRole("heading", { name: "Starting the WyVPN service…" })).toBeInTheDocument();
    expect(screen.getByText("This screen continues on its own once the service is ready.")).toBeInTheDocument();
    expect(screen.queryByText(/isn't running/)).not.toBeInTheDocument();
    expect(screen.queryByText("/var/run/wyvpn.sock")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("explains the delay with the socket and a settings button after 30 seconds", async () => {
    render(DaemonStarting, { socket: "/var/run/wyvpn.sock" });

    await vi.advanceTimersByTimeAsync(29_999);
    expect(screen.queryByText(/taking longer than expected/)).not.toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(1);
    expect(
      screen.getByRole("heading", { name: "The WyVPN service is taking longer than expected" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Allow in the Background/)).toBeInTheDocument();
    expect(screen.getByText("Looking for")).toBeInTheDocument();
    expect(screen.getByText("/var/run/wyvpn.sock")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open System Settings" })).toBeInTheDocument();
  });

  it("omits the socket line when the path is empty", async () => {
    render(DaemonStarting, { socket: "" });
    await vi.advanceTimersByTimeAsync(30_000);

    expect(screen.getByText(/taking longer than expected/)).toBeInTheDocument();
    expect(screen.queryByText("Looking for")).not.toBeInTheDocument();
  });

  it("opens Login Items from the settings button", async () => {
    render(DaemonStarting, { socket: "/var/run/wyvpn.sock" });
    await vi.advanceTimersByTimeAsync(30_000);

    await fireEvent.click(screen.getByRole("button", { name: "Open System Settings" }));
    expect(invoke).toHaveBeenCalledWith("open_login_items", undefined);
  });

  it("refreshes availability once the service is no longer enabled", async () => {
    let status = "enabled";
    invoke.mockImplementation(async (command: string) => {
      if (command === "service_status") return status;
      if (command === "daemon_state") return { available: false, socket: "/s", status: "needs_setup" };
      return null;
    });
    render(DaemonStarting, { socket: "/s" });
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("service_status", undefined));
    expect(invoke).not.toHaveBeenCalledWith("daemon_state", undefined);

    status = "requires_approval";
    await vi.advanceTimersByTimeAsync(2000);
    expect(invoke).toHaveBeenCalledWith("daemon_state", undefined);
  });

  describe("repair", () => {
    async function openSlow() {
      render(DaemonStarting, { socket: "/s" });
      await vi.advanceTimersByTimeAsync(30_000);
    }

    it("is offered only after the grace period", async () => {
      render(DaemonStarting, { socket: "/s" });
      await vi.advanceTimersByTimeAsync(29_999);
      expect(screen.queryByRole("button", { name: "Repair background service" })).not.toBeInTheDocument();

      await vi.advanceTimersByTimeAsync(1);
      expect(screen.getByRole("button", { name: "Repair background service" })).toBeEnabled();
    });

    it("runs the repair, disables itself meanwhile and refreshes availability", async () => {
      let finish: (status: string) => void = () => {};
      invoke.mockImplementation((command: string) => {
        if (command === "repair_service") return new Promise((resolve) => (finish = resolve));
        if (command === "daemon_state") return Promise.resolve({ available: false, socket: "/s", status: "starting" });
        return Promise.resolve(null);
      });
      await openSlow();

      await fireEvent.click(screen.getByRole("button", { name: "Repair background service" }));
      const busy = screen.getByRole("button", { name: "Repairing…" });
      expect(busy).toBeDisabled();
      expect(invoke).toHaveBeenCalledWith("repair_service", undefined);

      finish("enabled");
      await vi.waitFor(() => expect(screen.getByText(/Service repaired/)).toBeInTheDocument());
      expect(invoke).toHaveBeenCalledWith("daemon_state", undefined);
      expect(screen.getByRole("button", { name: "Repair background service" })).toBeEnabled();
    });

    it("shows the failure and allows another attempt", async () => {
      invoke.mockImplementation((command: string) =>
        command === "repair_service"
          ? Promise.reject({ code: "service_setup", message: "denied" })
          : Promise.resolve(null),
      );
      await openSlow();

      await fireEvent.click(screen.getByRole("button", { name: "Repair background service" }));
      await vi.waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
      expect(screen.queryByText(/Service repaired/)).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Repair background service" })).toBeEnabled();
    });

    it("picks up a launch error that arrives after the panel opened", async () => {
      let recorded: string | null = null;
      invoke.mockImplementation((command: string) =>
        Promise.resolve(command === "service_error" ? recorded : null),
      );
      await openSlow();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();

      recorded = "could not register";
      await vi.advanceTimersByTimeAsync(2000);
      expect(screen.getByRole("alert")).toHaveTextContent(/could not register/);

      recorded = null;
      await vi.advanceTimersByTimeAsync(2000);
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("shows an error recorded at launch", async () => {
      invoke.mockImplementation((command: string) =>
        Promise.resolve(command === "service_error" ? "could not register" : null),
      );
      await openSlow();

      expect(screen.getByRole("alert")).toHaveTextContent(/could not register/);
    });
  });

  it("clears its timers on unmount", () => {
    const { unmount } = render(DaemonStarting, { socket: "/s" });
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
