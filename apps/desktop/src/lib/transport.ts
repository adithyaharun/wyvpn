import type { Transport } from "./types";

const PREFERENCE: readonly Transport[] = ["open_vpn", "wire_guard"];

export function transportChoices(transports: readonly Transport[]): Transport[] {
  return PREFERENCE.filter((transport) => transports.includes(transport));
}

export function defaultTransport(transports: readonly Transport[]): Transport | undefined {
  return transportChoices(transports)[0];
}
