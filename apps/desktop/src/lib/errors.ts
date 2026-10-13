import type { ErrorBody, ErrorCode } from "./types";

const KNOWN_CODES: readonly ErrorCode[] = [
  "not_implemented",
  "not_found",
  "invalid_request",
  "invalid_state",
  "already_exists",
  "unsupported_auth",
  "auth_failed",
  "timeout",
  "server",
  "internal",
  "daemon_unavailable",
  "too_large",
  "io",
  "permission_denied",
  "service_setup",
];

export class CommandError extends Error implements ErrorBody {
  readonly code: ErrorCode;
  readonly retry?: string;

  constructor(code: ErrorCode, message: string, retry?: string) {
    super(message);
    this.name = "CommandError";
    this.code = code;
    if (retry !== undefined) this.retry = retry;
  }

  toBody(): ErrorBody {
    return this.retry === undefined
      ? { code: this.code, message: this.message }
      : { code: this.code, message: this.message, retry: this.retry };
  }
}

function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === "string" && (KNOWN_CODES as readonly string[]).includes(value);
}

export function toCommandError(error: unknown): CommandError {
  if (error instanceof CommandError) return error;
  if (typeof error === "object" && error !== null) {
    const { code, message, retry } = error as { code?: unknown; message?: unknown; retry?: unknown };
    const text = typeof message === "string" ? message : "";
    const token = typeof retry === "string" && retry ? retry : undefined;
    return new CommandError(isErrorCode(code) ? code : "internal", text, token);
  }
  return new CommandError("internal", typeof error === "string" ? error : "");
}

export function describeError(error: ErrorBody): string {
  switch (error.code) {
    case "auth_failed":
      return "The PIN was rejected. Try again.";
    case "daemon_unavailable":
      return "The WyVPN service isn't running. Start wyvpnd and try again.";
    case "permission_denied":
      return "Your account isn't allowed to do that. Ask an administrator.";
    case "too_large":
      return "That file is too large to be a profile. Choose a different file.";
    case "io":
      return "The file couldn't be read. Check that you can open it and try again.";
    case "timeout":
      return "The server didn't respond in time. Check your network and try again.";
    case "unsupported_auth":
      return "This profile uses a sign-in method that isn't supported yet.";
    default:
      return error.message || "Something went wrong. Try again.";
  }
}

export function isDuplicateImport(error: ErrorBody): boolean {
  return error.code === "already_exists";
}

export function duplicateName(error: ErrorBody): string | null {
  const match = /profile\s+["']?(.+?)["']?\s+already exists/i.exec(error.message);
  return match ? match[1] : null;
}

// An older daemon rejects new request types while decoding, as serde's "unknown variant".
const UNKNOWN_REQUEST = /unknown variant/i;

export function isUnknownRequest(error: ErrorBody): boolean {
  return error.code === "invalid_request" && UNKNOWN_REQUEST.test(error.message);
}

export const OUTDATED_RENAME = "Renaming needs a newer WyVPN service. Update the daemon, then try again.";
export const OUTDATED_LOG = "The connection log needs a newer WyVPN service. Update the daemon, then open the log again.";

export function describeRenameError(error: ErrorBody): string {
  if (isUnknownRequest(error)) return OUTDATED_RENAME;
  if (error.code === "not_found") return "This profile no longer exists. It may have been removed.";
  return describeError(error);
}

export function describeLogError(error: ErrorBody): string {
  // The log request has no arguments, so invalid_request only comes from an older daemon.
  if (error.code === "invalid_request") return OUTDATED_LOG;
  return describeError(error);
}
