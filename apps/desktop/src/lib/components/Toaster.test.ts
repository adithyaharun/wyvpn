import { fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
const copyText = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("$lib/clipboard", () => ({ copyText }));

import { TOAST_LIFETIME, toasts } from "$lib/toast.svelte";
import Toaster from "./Toaster.svelte";

function raise(error: unknown) {
  window.dispatchEvent(new ErrorEvent("error", { error, message: error instanceof Error ? error.message : "" }));
}

describe("Toaster", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockImplementation(async (command: string) =>
      command === "app_info" ? { version: "0.1.0", os: "macOS", arch: "aarch64" } : null,
    );
    copyText.mockReset();
    copyText.mockResolvedValue(undefined);
  });

  afterEach(() => {
    toasts.clear();
    vi.useRealTimers();
  });

  it("shows a toast for an uncaught error", async () => {
    render(Toaster);
    raise(new Error("Cannot read properties of undefined"));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Something went wrong in WyVPN.");
    expect(alert).toHaveTextContent("Cannot read properties of undefined");
  });

  it("shows a toast for an unhandled rejection", async () => {
    render(Toaster);
    window.dispatchEvent(Object.assign(new Event("unhandledrejection"), { reason: new Error("rejected") }));
    expect(await screen.findByText("rejected")).toBeInTheDocument();
  });

  it("renders error text literally", async () => {
    const markup = "<img src=x onerror=alert(1)> <b>bold</b>";
    const { container } = render(Toaster);
    raise(new Error(markup));
    expect(await screen.findByText(markup)).toBeInTheDocument();
    expect(container.querySelector("img, b")).toBeNull();
  });

  it("copies the error details with the app version", async () => {
    render(Toaster);
    const error = new TypeError("boom");
    error.stack = "TypeError: boom\n    at run (app.js:1:1)";
    raise(error);

    await fireEvent.click(await screen.findByRole("button", { name: "Copy details" }));

    await vi.waitFor(() =>
      expect(copyText).toHaveBeenCalledWith("WyVPN 0.1.0 (macOS aarch64)\nTypeError: boom\n    at run (app.js:1:1)"),
    );
    expect(invoke).toHaveBeenCalledWith("app_info", undefined);
  });

  it("copies details without the version on an older backend", async () => {
    invoke.mockRejectedValue("unknown command app_info");
    render(Toaster);
    raise(new Error("plain"));

    await fireEvent.click(await screen.findByRole("button", { name: "Copy details" }));

    await vi.waitFor(() => expect(copyText).toHaveBeenCalledWith(expect.stringMatching(/^Error: plain/)));
  });

  it("dismisses", async () => {
    render(Toaster);
    raise(new Error("go away"));
    await fireEvent.click(await screen.findByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("stays while hovered", async () => {
    vi.useFakeTimers();
    render(Toaster);
    raise(new Error("hold on"));
    const alert = await screen.findByRole("alert");

    await fireEvent.mouseEnter(alert);
    vi.advanceTimersByTime(TOAST_LIFETIME * 2);
    expect(toasts.items).toHaveLength(1);

    await fireEvent.mouseLeave(alert);
    vi.advanceTimersByTime(TOAST_LIFETIME);
    expect(toasts.items).toHaveLength(0);
  });

  it("ignores ResizeObserver loop noise", () => {
    render(Toaster);
    window.dispatchEvent(new ErrorEvent("error", { message: "ResizeObserver loop limit exceeded" }));
    expect(toasts.items).toHaveLength(0);
  });
});
