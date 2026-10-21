import { describe, expect, it } from "vitest";
import { defaultTransport, transportChoices } from "./transport";
import type { Transport } from "./types";

describe("transport choices", () => {
  it("offers only OpenVPN for an OpenVPN-only profile", () => {
    expect(transportChoices(["open_vpn"])).toEqual(["open_vpn"]);
    expect(defaultTransport(["open_vpn"])).toBe("open_vpn");
  });

  it("lists OpenVPN first and defaults to it when both are available", () => {
    expect(transportChoices(["wire_guard", "open_vpn"])).toEqual(["open_vpn", "wire_guard"]);
    expect(defaultTransport(["wire_guard", "open_vpn"])).toBe("open_vpn");
  });

  it("defaults to WireGuard when the profile has no OpenVPN", () => {
    expect(transportChoices(["wire_guard"])).toEqual(["wire_guard"]);
    expect(defaultTransport(["wire_guard"])).toBe("wire_guard");
  });

  it("leaves the choice to the daemon when the profile lists no transports", () => {
    expect(transportChoices([])).toEqual([]);
    expect(defaultTransport([])).toBeUndefined();
  });

  it("drops duplicates and unknown values", () => {
    expect(transportChoices(["open_vpn", "open_vpn", "ikev2"] as Transport[])).toEqual(["open_vpn"]);
  });
});
