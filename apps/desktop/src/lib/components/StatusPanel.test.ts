import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionStatus } from "$lib/types";

const copyText = vi.hoisted(() => vi.fn());
vi.mock("$lib/clipboard", () => ({ copyText }));

import StatusPanel from "./StatusPanel.svelte";

const connected: ConnectionStatus = {
  profile_id: "p1",
  profile_name: "Office",
  state: "connected",
  transport: "open_vpn",
  tunnel_ip: "10.0.0.2",
  local_ip: "192.168.1.20",
  server_endpoint: "vpn.example.com:443",
  connected_since: null,
  rx_bytes: 0,
  tx_bytes: 0,
};

describe("StatusPanel", () => {
  beforeEach(() => {
    copyText.mockReset();
    copyText.mockResolvedValue(undefined);
  });

  it("shows the local IP with copy controls for each address", () => {
    render(StatusPanel, { session: connected });
    expect(screen.getByText("Local IP")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.20")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy tunnel IP" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy local IP" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy endpoint" })).toBeInTheDocument();
  });

  it("copies each address and confirms the copy", async () => {
    render(StatusPanel, { session: connected });

    await fireEvent.click(screen.getByRole("button", { name: "Copy tunnel IP" }));
    expect(copyText).toHaveBeenLastCalledWith("10.0.0.2");
    expect(await screen.findByText("Copied")).toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Copy local IP" }));
    expect(copyText).toHaveBeenLastCalledWith("192.168.1.20");

    await fireEvent.click(screen.getByRole("button", { name: "Copy endpoint" }));
    expect(copyText).toHaveBeenLastCalledWith("vpn.example.com:443");
  });

  it("says so when the copy fails", async () => {
    copyText.mockRejectedValueOnce(new Error("denied"));
    render(StatusPanel, { session: connected });
    await fireEvent.click(screen.getByRole("button", { name: "Copy tunnel IP" }));
    expect(await screen.findByText("Couldn't copy. Try again.")).toBeInTheDocument();
  });

  it("hides the local IP row when the daemon doesn't report it", () => {
    const { local_ip: _, ...older } = connected;
    render(StatusPanel, { session: older });
    expect(screen.queryByText("Local IP")).toBeNull();
    expect(screen.queryByRole("button", { name: "Copy local IP" })).toBeNull();
  });

  it("offers no copy controls without a session", () => {
    render(StatusPanel, { session: null });
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("marks the state with a decorative icon that spins only while connecting", async () => {
    const { container, rerender } = render(StatusPanel, { session: connected });
    const icon = () => container.querySelector(".state svg");
    expect(icon()).toHaveAttribute("aria-hidden", "true");
    expect(icon()).toHaveClass("lucide-shield-check");
    expect(icon()).not.toHaveClass("spin");

    await rerender({ session: { ...connected, state: "connecting" } });
    expect(icon()).toHaveClass("spin");
  });

  it("prefers the profile's current name over the session's", () => {
    render(StatusPanel, {
      session: connected,
      profile: {
        id: "p1",
        name: "Work",
        imported_name: "Office",
        server_name: "gw",
        server_host: "vpn.example.com",
        user: "alice",
        auth_mode: "pin",
        transports: ["open_vpn"],
      },
    });
    expect(screen.getByText("Work", { exact: false })).toBeInTheDocument();
  });
});
