import { render, screen } from "@testing-library/svelte";
import { describe, expect, it } from "vitest";
import DaemonOutdated from "./DaemonOutdated.svelte";

describe("DaemonOutdated", () => {
  it("names the app and service versions", () => {
    render(DaemonOutdated, {
      mismatch: { client_version: "0.1.2", client_protocol: 1, daemon_version: "0.1.1", daemon_protocol: 1 },
    });

    expect(
      screen.getByRole("heading", { name: "The WyVPN service restarts after you disconnect" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("The background service runs a different version. It updates on its own once no tunnel is connected."),
    ).toBeInTheDocument();
    expect(screen.getByText("0.1.2")).toBeInTheDocument();
    expect(screen.getByText("0.1.1")).toBeInTheDocument();
    expect(screen.getByText("If this stays after you disconnect, restart your Mac.")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("falls back when the service sends no version", () => {
    render(DaemonOutdated, { mismatch: { client_version: "0.1.2", client_protocol: 1, daemon_version: null } });

    expect(screen.getByText("a different version")).toBeInTheDocument();
  });
});
