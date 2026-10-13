import { describe, expect, it } from "vitest";
import { describeError, duplicateName, isDuplicateImport, toCommandError } from "./errors";
import { formatBytes, formatUptime, joinNames, transportLabel } from "./format";

describe("format", () => {
  it("formats bytes in human units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(999)).toBe("999 B");
    expect(formatBytes(1_234)).toBe("1.2 KB");
    expect(formatBytes(345_000_000)).toBe("345 MB");
    expect(formatBytes(2_500_000_000)).toBe("2.5 GB");
  });

  it("formats uptime as a clock", () => {
    expect(formatUptime(0)).toBe("0:00:00");
    expect(formatUptime(3_723)).toBe("1:02:03");
    expect(formatUptime(90_061)).toBe("1d 1:01:01");
  });

  it("labels transports and joins names", () => {
    expect(transportLabel("wire_guard")).toBe("WireGuard");
    expect(transportLabel("open_vpn")).toBe("OpenVPN");
    expect(joinNames(["Office"])).toBe("Office");
    expect(joinNames(["A", "B", "C"])).toBe("A, B and C");
  });
});

describe("errors", () => {
  it("normalizes command rejections", () => {
    expect(toCommandError({ code: "auth_failed", message: "x" }).code).toBe("auth_failed");
    expect(toCommandError({ code: "weird", message: "x" }).code).toBe("internal");
    expect(toCommandError("boom").message).toBe("boom");
  });

  it("describes auth failures without echoing input", () => {
    expect(describeError({ code: "auth_failed", message: "bad pin 1234" })).toBe(
      "The PIN was rejected. Try again.",
    );
  });

  it("detects duplicate imports by code only", () => {
    const error = {
      code: "already_exists" as const,
      message: "profile Office already exists; use replace to overwrite",
    };
    expect(isDuplicateImport(error)).toBe(true);
    expect(duplicateName(error)).toBe("Office");
    expect(isDuplicateImport({ ...error, code: "invalid_state" })).toBe(false);
  });

  it("keeps the retry token from a rejection", () => {
    const error = toCommandError({ code: "already_exists", message: "x", retry: "tok" });
    expect(error.code).toBe("already_exists");
    expect(error.toBody()).toEqual({ code: "already_exists", message: "x", retry: "tok" });
    expect(toCommandError({ code: "already_exists", message: "x", retry: 7 }).toBody()).toEqual({
      code: "already_exists",
      message: "x",
    });
  });
});
