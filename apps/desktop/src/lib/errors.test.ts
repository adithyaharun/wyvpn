import { describe, expect, it } from "vitest";
import { describeLogError, describeRenameError, isUnknownRequest, OUTDATED_LOG, OUTDATED_RENAME } from "./errors";

describe("older daemon detection", () => {
  const unknown = {
    code: "invalid_request" as const,
    message: "unknown variant `rename_profile`, expected one of `list_profiles`, `connect` at line 1 column 40",
  };
  const badName = { code: "invalid_request" as const, message: "name must be at most 64 characters" };

  it("recognises an unknown request type", () => {
    expect(isUnknownRequest(unknown)).toBe(true);
    expect(isUnknownRequest(badName)).toBe(false);
    expect(isUnknownRequest({ code: "internal", message: "unknown variant" })).toBe(false);
  });

  it("asks to update the daemon only when rename is unknown", () => {
    expect(describeRenameError(unknown)).toBe(OUTDATED_RENAME);
    expect(OUTDATED_RENAME).toContain("Update the daemon");
    expect(describeRenameError(badName)).toBe("name must be at most 64 characters");
  });

  it("treats any invalid log request as an older daemon", () => {
    expect(describeLogError({ code: "invalid_request", message: "anything" })).toBe(OUTDATED_LOG);
    expect(OUTDATED_LOG).toContain("Update the daemon");
    expect(describeLogError({ code: "timeout", message: "" })).toContain("didn't respond");
  });
});
