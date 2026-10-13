export type AuthMode = "none" | "pin" | "otp" | "pin_otp" | "sso";

export type Transport = "wire_guard" | "open_vpn";

export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "error";

export type DaemonErrorCode =
  | "not_implemented"
  | "not_found"
  | "invalid_request"
  | "invalid_state"
  | "already_exists"
  | "unsupported_auth"
  | "auth_failed"
  | "timeout"
  | "server"
  | "internal"
  | "permission_denied";

export type ErrorCode = DaemonErrorCode | "daemon_unavailable" | "too_large" | "io" | "service_setup";

export interface ErrorBody {
  code: ErrorCode;
  message: string;
  retry?: string;
}

export interface ProfileSummary {
  id: string;
  name: string;
  server_name: string;
  server_host: string;
  user: string;
  auth_mode: AuthMode;
  transports: Transport[];
  imported_name?: string;
}

export interface ConnectionStatus {
  profile_id: string;
  profile_name: string;
  state: ConnectionState;
  transport: Transport | null;
  tunnel_ip: string | null;
  local_ip?: string | null;
  server_endpoint: string | null;
  connected_since: number | null;
  rx_bytes: number;
  tx_bytes: number;
  error?: ErrorBody | null;
  awaiting?: AuthMode;
}

export type DaemonStatus =
  | "available"
  | "unreachable"
  | "starting"
  | "incompatible"
  | "not_permitted"
  | "needs_setup";

export type ServiceStatus = "not_registered" | "enabled" | "requires_approval" | "not_found";

export interface VersionMismatch {
  client_version: string;
  client_protocol: number;
  daemon_version?: string | null;
  daemon_protocol?: number | null;
}

export interface DaemonAvailability {
  available: boolean;
  socket: string;
  status?: DaemonStatus;
  mismatch?: VersionMismatch;
  setup?: ServiceStatus;
}

export interface OpenVpnNotice {
  license: string;
  source_url: string | null;
}

export type DaemonEvent =
  | { type: "state_changed"; profile_id: string; state: ConnectionState; error?: ErrorBody | null }
  | { type: "credentials_required"; profile_id: string; mode: AuthMode }
  | { type: "stats"; profile_id: string; rx_bytes: number; tx_bytes: number }
  | { type: "profiles_changed" }
  | { type: "log"; profile_id: string; lines: LogLine[] };

export type LogSource = "tunnel" | "daemon";

export interface LogLine {
  seq: number;
  at_ms: number;
  source: LogSource;
  text: string;
}

export interface SessionLog {
  profile_id: string | null;
  lines: LogLine[];
}

export interface Settings {
  auto_connect_profile_id: string | null;
  auto_reconnect: boolean;
  notifications: boolean;
}

export interface StartupNotice {
  profile_id: string;
}

export type NotificationPermission = "granted" | "denied" | "prompt";

export interface PendingCredentials {
  profileId: string;
  mode: AuthMode;
}

export type BusyAction = "connect" | "disconnect" | "remove";

export interface AppInfo {
  version: string;
  os: string;
  arch: string;
}

export type SupportTarget = "project" | "issue" | "openvpn_source";
