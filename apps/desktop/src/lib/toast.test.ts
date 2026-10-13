import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TOAST_LIFETIME, TOAST_LIMIT, captureErrors, errorDetails, formatDetails, toasts } from "./toast.svelte";

const messages = () => toasts.items.map((toast) => toast.message);

describe("toast store", () => {
  beforeEach(() => vi.useFakeTimers());

  afterEach(() => {
    toasts.clear();
    vi.useRealTimers();
  });

  it("adds a toast for an error", () => {
    const toast = toasts.report(new TypeError("boom"));
    expect(toast).toMatchObject({ name: "TypeError", message: "boom" });
    expect(toasts.items).toHaveLength(1);
  });

  it("de-duplicates identical messages", () => {
    const first = toasts.report(new Error("same"));
    const second = toasts.report(new Error("same"));
    expect(second?.id).toBe(first?.id);
    expect(messages()).toEqual(["same"]);
  });

  it("keeps only the newest toasts", () => {
    for (let i = 0; i < TOAST_LIMIT + 2; i++) toasts.report(new Error(`error ${i}`));
    expect(messages()).toEqual(["error 2", "error 3", "error 4"]);
  });

  it("dismisses after a while", () => {
    toasts.report(new Error("fades"));
    vi.advanceTimersByTime(TOAST_LIFETIME - 1);
    expect(toasts.items).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(toasts.items).toHaveLength(0);
  });

  it("pauses while hovered or focused", () => {
    const toast = toasts.report(new Error("held"));
    if (!toast) throw new Error("no toast");

    vi.advanceTimersByTime(TOAST_LIFETIME - 1000);
    toasts.pause(toast.id, "hover");
    toasts.pause(toast.id, "focus");
    vi.advanceTimersByTime(TOAST_LIFETIME * 2);
    expect(toasts.items).toHaveLength(1);

    toasts.resume(toast.id, "hover");
    vi.advanceTimersByTime(TOAST_LIFETIME * 2);
    expect(toasts.items).toHaveLength(1);

    toasts.resume(toast.id, "focus");
    vi.advanceTimersByTime(1999);
    expect(toasts.items).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(toasts.items).toHaveLength(0);
  });

  it("dismisses on request", () => {
    const toast = toasts.report(new Error("bye"));
    if (!toast) throw new Error("no toast");
    toasts.dismiss(toast.id);
    expect(toasts.items).toHaveLength(0);
  });

  it("ignores ResizeObserver noise and extension errors", () => {
    expect(toasts.report(new Error("ResizeObserver loop completed with undelivered notifications."))).toBeNull();
    expect(toasts.report(new Error("x"), "chrome-extension://abc/content.js")).toBeNull();
    const fromExtension = new Error("y");
    fromExtension.stack = "Error: y\n    at moz-extension://abc/inject.js:1:1";
    expect(toasts.report(fromExtension)).toBeNull();
    expect(toasts.items).toHaveLength(0);
  });

  it("stops accepting reports during a burst", () => {
    for (let i = 0; i < 50; i++) toasts.report(new Error(`burst ${i}`));
    expect(messages()).toEqual(["burst 7", "burst 8", "burst 9"]);
  });

  it("never throws for odd values", () => {
    const hostile = {
      toString() {
        throw new Error("nope");
      },
    };
    expect(() => toasts.report(hostile)).not.toThrow();
    expect(() => toasts.report(undefined)).not.toThrow();
  });
});

describe("errorDetails", () => {
  it("reads errors, plain objects and strings", () => {
    expect(errorDetails(new RangeError("bad"))).toMatchObject({ name: "RangeError", message: "bad" });
    expect(errorDetails({ code: "io", message: "disk" })).toEqual({ name: "Error", message: "disk", stack: undefined });
    expect(errorDetails("plain")).toEqual({ name: "Error", message: "plain" });
  });
});

describe("formatDetails", () => {
  it("joins the version, error and stack without repeating the heading", () => {
    const details = { name: "TypeError", message: "boom", stack: "TypeError: boom\n    at run (app.js:1:1)" };
    expect(formatDetails(details, { version: "0.1.0", os: "macOS", arch: "aarch64" })).toBe(
      "WyVPN 0.1.0 (macOS aarch64)\nTypeError: boom\n    at run (app.js:1:1)",
    );
  });

  it("leaves out what isn't known", () => {
    expect(formatDetails({ name: "Error", message: "x" }, null)).toBe("Error: x");
  });
});

describe("captureErrors", () => {
  let release: () => void;

  beforeEach(() => {
    release = captureErrors(window);
  });

  afterEach(() => {
    release();
    toasts.clear();
  });

  it("reports uncaught errors", () => {
    window.dispatchEvent(new ErrorEvent("error", { error: new Error("uncaught"), message: "uncaught" }));
    expect(messages()).toEqual(["uncaught"]);
  });

  it("reports unhandled rejections", () => {
    const event = Object.assign(new Event("unhandledrejection"), { reason: new Error("rejected") });
    window.dispatchEvent(event);
    expect(messages()).toEqual(["rejected"]);
  });

  it("skips errors from browser extensions", () => {
    window.dispatchEvent(
      new ErrorEvent("error", { error: new Error("ext"), message: "ext", filename: "safari-web-extension://x/a.js" }),
    );
    expect(toasts.items).toHaveLength(0);
  });

  it("stops listening when released", () => {
    release();
    window.dispatchEvent(Object.assign(new Event("unhandledrejection"), { reason: new Error("late") }));
    expect(toasts.items).toHaveLength(0);
  });
});
