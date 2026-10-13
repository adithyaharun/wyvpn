import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { daemon } from "$lib/daemon.svelte";
import PinDialog from "./PinDialog.svelte";

describe("PinDialog", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
  });

  it("focuses the PIN input", () => {
    render(PinDialog, { profileId: "p1", profileName: "Office", mode: "pin" });
    expect(screen.getByLabelText("PIN")).toHaveFocus();
  });

  it("sends the PIN and clears the input on submit", async () => {
    render(PinDialog, { profileId: "p1", profileName: "Office", mode: "pin" });
    const input = screen.getByLabelText<HTMLInputElement>("PIN");

    await fireEvent.input(input, { target: { value: "4321" } });
    await fireEvent.click(screen.getByRole("button", { name: "Connect" }));

    expect(invoke).toHaveBeenCalledWith("submit_pin", { profileId: "p1", pin: "4321" });
    expect(input.value).toBe("");
    expect(JSON.stringify(daemon.state)).not.toContain("4321");
    expect(JSON.stringify(daemon.lastError)).not.toContain("4321");
  });

  it("keeps the PIN out of errors when submit fails", async () => {
    invoke.mockRejectedValueOnce({ code: "auth_failed", message: "rejected" });
    render(PinDialog, { profileId: "p1", profileName: "Office", mode: "pin" });
    const input = screen.getByLabelText<HTMLInputElement>("PIN");

    await fireEvent.input(input, { target: { value: "9876" } });
    await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await vi.waitFor(() => expect(daemon.lastError?.code).toBe("auth_failed"));

    expect(JSON.stringify(daemon.lastError)).not.toContain("9876");
    daemon.dismissError();
  });

  it("cancels the request and clears the input", async () => {
    render(PinDialog, { profileId: "p1", profileName: "Office", mode: "pin" });
    const input = screen.getByLabelText<HTMLInputElement>("PIN");

    await fireEvent.input(input, { target: { value: "1111" } });
    await fireEvent.click(screen.getByRole("button", { name: "Close" }));

    expect(invoke).toHaveBeenCalledWith("cancel_credentials", { profileId: "p1" });
    expect(invoke).not.toHaveBeenCalledWith("submit_pin", expect.anything());
    expect(input.value).toBe("");
  });

  it("cancels on a backdrop click", async () => {
    const { container } = render(PinDialog, { profileId: "p1", profileName: "Office", mode: "pin" });
    await fireEvent.click(container.ownerDocument.querySelector(".scrim")!);
    expect(invoke).toHaveBeenCalledWith("cancel_credentials", { profileId: "p1" });
  });

  it("cancels on Escape", async () => {
    render(PinDialog, { profileId: "p1", profileName: "Office", mode: "pin" });
    await fireEvent.keyDown(window, { key: "Escape" });
    expect(invoke).toHaveBeenCalledWith("cancel_credentials", { profileId: "p1" });
  });

  it("shows the unsupported view without an input for other modes", async () => {
    const { container } = render(PinDialog, { profileId: "p1", profileName: "Office", mode: "otp" });

    expect(screen.getByText("This sign-in method isn't supported yet.")).toBeInTheDocument();
    expect(container.ownerDocument.querySelector("input")).toBeNull();
    expect(
      screen.getAllByRole("button").map((b) => b.getAttribute("aria-label") ?? b.textContent?.trim()),
    ).toEqual(["Close"]);

    await fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(invoke).toHaveBeenCalledWith("cancel_credentials", { profileId: "p1" });
  });
});
