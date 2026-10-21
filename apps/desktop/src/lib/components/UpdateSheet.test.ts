import { fireEvent, render, screen } from "@testing-library/svelte";
import { tick } from "svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { UpdateOffer, UpdateState } from "$lib/types";
import { updates } from "$lib/update.svelte";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import UpdateSheet from "./UpdateSheet.svelte";

function offer(overrides: Partial<UpdateOffer> = {}): UpdateOffer {
  return {
    version: "0.3.0",
    notes: "Faster reconnects\nFixed the tray icon",
    date: "2026-10-20T10:00:00Z",
    installable: true,
    release_url: "https://github.com/adithyaharun/wyvpn/releases/tag/v0.3.0",
    ...overrides,
  };
}

function show(state: UpdateState, vpnActive = false) {
  updates.state = state;
  updates.open = true;
  return render(UpdateSheet, { vpnActive });
}

const button = (name: string) => screen.getByRole("button", { name });

describe("UpdateSheet", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
    updates.state = { state: "idle" };
    updates.open = false;
    updates.error = null;
  });

  it("shows the version, date and notes with Install and Later", () => {
    show({ state: "available", ...offer() });
    expect(screen.getByRole("dialog", { name: "Software update" })).toBeInTheDocument();
    expect(screen.getByText("WyVPN 0.3.0 is available")).toBeInTheDocument();
    expect(screen.getByText(/^Released /)).toBeInTheDocument();
    const notes = screen.getByRole("region", { name: "Release notes" });
    expect(notes.textContent).toBe("Faster reconnects\nFixed the tray icon");
    expect(button("Install")).toBeEnabled();
    expect(button("Later")).toBeEnabled();
  });

  it("renders notes that look like HTML as text", () => {
    const notes = '<img src=x onerror="alert(1)"><b>bold</b>';
    show({ state: "available", ...offer({ notes }) });
    const region = screen.getByRole("region", { name: "Release notes" });
    expect(region.textContent).toBe(notes);
    expect(region.querySelector("img, b")).toBeNull();
  });

  it("omits the notes box when there are no notes", () => {
    show({ state: "available", ...offer({ notes: "", date: null }) });
    expect(screen.queryByRole("region", { name: "Release notes" })).toBeNull();
    expect(screen.queryByText(/^Released /)).toBeNull();
  });

  it("warns that installing disconnects only while a session is active", () => {
    const { unmount } = show({ state: "available", ...offer() }, true);
    expect(screen.getByRole("note")).toHaveTextContent("Installing disconnects the VPN.");
    unmount();

    show({ state: "available", ...offer() }, false);
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("Install calls install_update", async () => {
    show({ state: "available", ...offer() }, true);
    await fireEvent.click(button("Install"));
    expect(invoke).toHaveBeenCalledWith("install_update", undefined);
  });

  it("moves focus to the progress view after Install", async () => {
    show({ state: "available", ...offer() });
    const dialog = screen.getByRole("dialog", { name: "Software update" });
    const install = button("Install");
    install.focus();
    await fireEvent.click(install);
    updates.state = { state: "disconnecting", version: "0.3.0" };

    await vi.waitFor(() => expect(document.activeElement).toBe(screen.getByRole("status")));
    expect(dialog).toContainElement(document.activeElement as HTMLElement);

    updates.state = { state: "downloading", version: "0.3.0", received: 1, total: 2 };
    await tick();
    expect(document.activeElement).toBe(screen.getByRole("status"));
  });

  it("moves focus off the bare dialog when the install starts", async () => {
    show({ state: "available", ...offer() });
    const dialog = screen.getByRole("dialog", { name: "Software update" });
    expect(document.activeElement).toBe(dialog);
    updates.state = { state: "disconnecting", version: "0.3.0" };
    await vi.waitFor(() => expect(document.activeElement).toBe(screen.getByRole("status")));
  });

  it("focuses the progress view when the sheet opens mid-install", async () => {
    show({ state: "downloading", version: "0.3.0", received: 1, total: null });
    await vi.waitFor(() => expect(document.activeElement).toBe(screen.getByRole("status")));
  });

  it("Later calls dismiss_update and closes the sheet", async () => {
    invoke.mockImplementation(async (command: string) =>
      command === "dismiss_update" ? { state: "dismissed", ...offer() } : null,
    );
    show({ state: "available", ...offer() });
    await fireEvent.click(button("Later"));
    expect(invoke).toHaveBeenCalledWith("dismiss_update", undefined);
    expect(updates.open).toBe(false);
  });

  it("Escape means Later when nothing runs", async () => {
    show({ state: "available", ...offer() });
    await fireEvent.keyDown(window, { key: "Escape" });
    expect(invoke).toHaveBeenCalledWith("dismiss_update", undefined);
    expect(updates.open).toBe(false);
  });

  it("shows the disconnect step with the buttons disabled", async () => {
    show({ state: "disconnecting", version: "0.3.0" });
    expect(screen.getByText("Installing WyVPN 0.3.0")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Disconnecting the VPN…");
    expect(button("Install")).toBeDisabled();
    expect(button("Later")).toBeDisabled();
    expect(button("Close")).toBeDisabled();

    await fireEvent.keyDown(window, { key: "Escape" });
    expect(updates.open).toBe(true);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("shows a percentage when the download size is known", () => {
    show({ state: "downloading", version: "0.3.0", received: 3_000_000, total: 12_000_000 });
    expect(screen.getByRole("status")).toHaveTextContent("3.0 MB of 12.0 MB (25%)");
    const bar = screen.getByRole("progressbar");
    expect(bar).toHaveAttribute("value", "25");
    expect(bar).toHaveAttribute("max", "100");
  });

  it("shows bytes only when the download size is unknown", () => {
    show({ state: "downloading", version: "0.3.0", received: 3_000_000, total: null });
    expect(screen.getByRole("status")).toHaveTextContent(/Downloading… 3\.0 MB$/);
    expect(screen.getByRole("status").textContent).not.toMatch(/%/);
    expect(screen.getByRole("progressbar")).not.toHaveAttribute("value");
  });

  it("shows the installing and relaunching steps", () => {
    const { unmount } = show({ state: "installing", version: "0.3.0" });
    expect(screen.getByRole("status")).toHaveTextContent("Installing…");
    unmount();

    show({ state: "relaunching", version: "0.3.0" });
    expect(screen.getByText("Restarting WyVPN")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Restarting…");
  });

  it("shows an error with Check again", async () => {
    show({ state: "failed", message: "The update could not be verified. Nothing was installed." });
    expect(screen.getByRole("alert")).toHaveTextContent("The update could not be verified.");
    expect(screen.queryByRole("button", { name: "Install" })).toBeNull();

    await fireEvent.click(button("Check again"));
    expect(invoke).toHaveBeenCalledWith("check_for_updates", undefined);
  });

  it("shows the up-to-date result", async () => {
    show({ state: "up_to_date" });
    expect(screen.getByText("WyVPN is up to date")).toBeInTheDocument();
    await fireEvent.click(button("OK"));
    expect(updates.open).toBe(false);
  });

  it("shows a release page link and no Install on Linux", async () => {
    invoke.mockImplementation(async (command: string) =>
      command === "dismiss_update" ? { state: "dismissed", ...offer({ installable: false }) } : null,
    );
    show({ state: "available", ...offer({ installable: false }) }, true);
    expect(screen.getByText("Version 0.3.0 available")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Install" })).toBeNull();
    expect(screen.queryByRole("note")).toBeNull();

    await fireEvent.click(button("Open release page"));
    expect(invoke).toHaveBeenCalledWith("open_update_page", undefined);
    await vi.waitFor(() => expect(updates.open).toBe(false));
  });

  it("keeps the sheet open when the browser cannot open", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "open_update_page") throw { code: "internal", message: "could not open the browser" };
      return null;
    });
    show({ state: "available", ...offer({ installable: false }) });
    await fireEvent.click(button("Open release page"));
    expect(await screen.findByRole("alert")).toHaveTextContent("WyVPN couldn't open your browser.");
    expect(updates.open).toBe(true);
  });
});
