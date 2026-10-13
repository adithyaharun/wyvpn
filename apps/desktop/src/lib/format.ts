import type { AppInfo, ConnectionState, Transport } from "./types";

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"];

export function formatBytes(bytes: number): string {
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1000 && unit < BYTE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  if (unit === 0) return `${value} B`;
  const digits = value < 100 ? 1 : 0;
  return `${value.toFixed(digits)} ${BYTE_UNITS[unit]}`;
}

export function formatUptime(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  const clock = `${hours}:${String(minutes).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  return days > 0 ? `${days}d ${clock}` : clock;
}

const TRANSPORT_LABELS: Record<Transport, string> = {
  wire_guard: "WireGuard",
  open_vpn: "OpenVPN",
};

export function transportLabel(transport: Transport): string {
  return TRANSPORT_LABELS[transport] ?? transport;
}

const STATE_LABELS: Record<ConnectionState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  disconnecting: "Disconnecting",
  error: "Error",
};

export function stateLabel(state: ConnectionState): string {
  return STATE_LABELS[state];
}

export function joinNames(names: string[]): string {
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

export function formatClock(ms: number): string {
  const date = new Date(ms);
  return [date.getHours(), date.getMinutes(), date.getSeconds()]
    .map((part) => String(part).padStart(2, "0"))
    .join(":");
}

export function formatAppVersion(info: AppInfo): string {
  return `WyVPN ${info.version} (${info.os} ${info.arch})`;
}
