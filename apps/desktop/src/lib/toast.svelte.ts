import { untrack } from "svelte";
import { formatAppVersion } from "./format";
import type { AppInfo } from "./types";

export interface ErrorDetails {
  name: string;
  message: string;
  stack?: string;
}

export interface Toast extends ErrorDetails {
  id: number;
}

export type Hold = "hover" | "focus";

export const TOAST_LIMIT = 3;
export const TOAST_LIFETIME = 8_000;
const RESUME_FLOOR = 2_000;
const BURST_LIMIT = 10;
const BURST_WINDOW = 10_000;

const NOISE = /ResizeObserver loop|^Script error\.?$/i;
const EXTENSION = /\b(?:chrome|moz|safari(?:-web)?|ms-browser)-extension:\/\//i;

function text(value: unknown): string {
  try {
    return String(value);
  } catch {
    return "";
  }
}

export function errorDetails(error: unknown): ErrorDetails {
  if (error instanceof Error) {
    return { name: error.name || "Error", message: text(error.message), stack: error.stack };
  }
  if (typeof error === "object" && error !== null) {
    const { name, message, stack } = error as { name?: unknown; message?: unknown; stack?: unknown };
    if (typeof message === "string") {
      return {
        name: typeof name === "string" && name ? name : "Error",
        message,
        stack: typeof stack === "string" ? stack : undefined,
      };
    }
  }
  return { name: "Error", message: error === undefined ? "" : text(error) };
}

export function isIgnorable(details: ErrorDetails, source?: string): boolean {
  return (
    NOISE.test(details.message) ||
    (source !== undefined && EXTENSION.test(source)) ||
    (details.stack !== undefined && EXTENSION.test(details.stack))
  );
}

export function formatDetails(details: ErrorDetails, info: AppInfo | null): string {
  const heading = details.message ? `${details.name}: ${details.message}` : details.name;
  const frames = details.stack?.startsWith(heading)
    ? details.stack.slice(heading.length).replace(/^\n/, "")
    : details.stack;
  return [info ? formatAppVersion(info) : null, heading, frames || null]
    .filter((line): line is string => line !== null)
    .join("\n");
}

interface Timer {
  handle: ReturnType<typeof setTimeout> | null;
  deadline: number;
  remaining: number;
  holds: Set<Hold>;
}

class ToastStore {
  items = $state<Toast[]>([]);
  #timers = new Map<number, Timer>();
  #recent: number[] = [];
  #next = 1;
  #reporting = false;

  report(error: unknown, source?: string): Toast | null {
    // Anything thrown while reporting is dropped so a broken report path can't feed itself.
    if (this.#reporting) return null;
    this.#reporting = true;
    try {
      return untrack(() => this.#add(errorDetails(error), source));
    } catch {
      return null;
    } finally {
      this.#reporting = false;
    }
  }

  dismiss(id: number): void {
    this.#stop(id);
    this.items = untrack(() => this.items.filter((toast) => toast.id !== id));
  }

  pause(id: number, hold: Hold): void {
    const timer = this.#timers.get(id);
    if (!timer) return;
    timer.holds.add(hold);
    if (timer.handle === null) return;
    clearTimeout(timer.handle);
    timer.handle = null;
    timer.remaining = Math.max(0, timer.deadline - Date.now());
  }

  resume(id: number, hold: Hold): void {
    const timer = this.#timers.get(id);
    if (!timer) return;
    timer.holds.delete(hold);
    if (timer.holds.size === 0 && timer.handle === null) {
      this.#schedule(id, timer, Math.max(timer.remaining, RESUME_FLOOR));
    }
  }

  clear(): void {
    for (const id of this.#timers.keys()) this.#stop(id);
    this.#recent = [];
    this.items = [];
  }

  #add(details: ErrorDetails, source?: string): Toast | null {
    if (isIgnorable(details, source)) return null;
    const existing = this.items.find((toast) => toast.name === details.name && toast.message === details.message);
    if (existing) return existing;

    const now = Date.now();
    this.#recent = this.#recent.filter((at) => now - at < BURST_WINDOW);
    if (this.#recent.length >= BURST_LIMIT) return null;
    this.#recent.push(now);

    const toast: Toast = { id: this.#next++, ...details };
    const items = [...this.items, toast];
    for (const dropped of items.slice(0, -TOAST_LIMIT)) this.#stop(dropped.id);
    this.items = items.slice(-TOAST_LIMIT);

    const timer: Timer = { handle: null, deadline: 0, remaining: TOAST_LIFETIME, holds: new Set() };
    this.#timers.set(toast.id, timer);
    this.#schedule(toast.id, timer, TOAST_LIFETIME);
    return toast;
  }

  #schedule(id: number, timer: Timer, delay: number): void {
    timer.deadline = Date.now() + delay;
    timer.handle = setTimeout(() => this.dismiss(id), delay);
  }

  #stop(id: number): void {
    const timer = this.#timers.get(id);
    if (timer?.handle) clearTimeout(timer.handle);
    this.#timers.delete(id);
  }
}

export const toasts = new ToastStore();

export function captureErrors(target: Window = window): () => void {
  const onerror = (event: ErrorEvent) => {
    if (event.error === undefined && !event.message) return;
    toasts.report(event.error ?? event.message, event.filename || undefined);
  };
  const onrejection = (event: PromiseRejectionEvent) => {
    toasts.report(event.reason);
  };
  target.addEventListener("error", onerror);
  target.addEventListener("unhandledrejection", onrejection);
  return () => {
    target.removeEventListener("error", onerror);
    target.removeEventListener("unhandledrejection", onrejection);
  };
}
