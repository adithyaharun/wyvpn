import "../app.css";
import { render, screen } from "@testing-library/svelte";
import { describe, expect, it, vi } from "vitest";
import type { ConnectionStatus } from "$lib/types";

vi.mock("$lib/clipboard", () => ({ copyText: vi.fn() }));

import ProfileList from "./components/ProfileList.svelte";
import StatusPanel from "./components/StatusPanel.svelte";

const session: ConnectionStatus = {
  profile_id: "p1",
  profile_name: "Office",
  state: "error",
  transport: "open_vpn",
  tunnel_ip: "10.0.0.2",
  local_ip: "192.168.1.20",
  server_endpoint: "vpn.example.com:443",
  connected_since: null,
  rx_bytes: 0,
  tx_bytes: 0,
  error: { code: "timeout", message: "timed out" },
};

const selectable = (element: Element) => getComputedStyle(element).getPropertyValue("user-select");

describe("text selection", () => {
  it("is off for the app and its labels", () => {
    render(StatusPanel, { session });
    expect(selectable(document.body)).toBe("none");
    expect(getComputedStyle(document.body).cursor).toBe("default");
    expect(selectable(screen.getByText("Tunnel IP"))).not.toBe("text");
    expect(selectable(screen.getByText("This device"))).not.toBe("text");
  });

  it("is on for addresses, endpoints and errors", () => {
    render(StatusPanel, { session });
    for (const value of ["10.0.0.2", "192.168.1.20", "vpn.example.com:443"]) {
      const element = screen.getByText(value);
      expect(selectable(element)).toBe("text");
      expect(getComputedStyle(element).cursor).toBe("text");
    }
    expect(selectable(screen.getByRole("alert"))).toBe("text");
  });

  it("is on for the profile server line and off for the profile name", () => {
    render(ProfileList, {
      profiles: [
        {
          id: "p1",
          name: "Office",
          server_name: "gw",
          server_host: "vpn.example.com",
          user: "alice",
          auth_mode: "pin",
          transports: ["open_vpn"],
        },
      ],
      statuses: {},
      busy: {},
      available: true,
      onconnect: vi.fn(),
      ondisconnect: vi.fn(),
      onremove: vi.fn(),
      onrename: vi.fn(async () => undefined),
      onimport: vi.fn(),
    });
    expect(selectable(screen.getByText("alice on vpn.example.com"))).toBe("text");
    expect(selectable(screen.getByRole("heading", { name: "Office" }))).not.toBe("text");
  });

  it("stays on for form fields", () => {
    const input = document.createElement("input");
    document.body.append(input);
    expect(selectable(input)).toBe("text");
    input.remove();
  });
});
