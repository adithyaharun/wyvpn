import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const INTERACTIVE = "button, input, select, textarea, a, [role='button']";

export function startWindowDrag(): void {
  invoke("plugin:window|start_dragging", { label: "main" }).catch(() => {});
}

export function dragWindow(event: MouseEvent): void {
  if (event.button !== 0) return;
  if (event.target instanceof Element && event.target.closest(INTERACTIVE)) return;
  startWindowDrag();
}

export interface WindowChrome {
  button_center_y: number;
  buttons_right: number;
}

export interface ToolbarChrome {
  padTop: number;
  padBottom: number;
  inset: number;
}

// Must match --toolbar in app.css.
export const TOOLBAR_HEIGHT = 40;
const BUTTON_HEIGHT = 28;
const BUTTONS_GAP = 16;

export function toolbarChrome(chrome: WindowChrome, toolbarHeight = TOOLBAR_HEIGHT): ToolbarChrome {
  const half = toolbarHeight / 2;
  const reach = Math.max(0, (toolbarHeight - BUTTON_HEIGHT) / 2);
  const center = Math.min(half + reach, Math.max(half - reach, chrome.button_center_y));
  return {
    padTop: 2 * Math.max(0, center - half),
    padBottom: 2 * Math.max(0, half - center),
    inset: Math.round(Math.max(0, chrome.buttons_right) + BUTTONS_GAP),
  };
}

function isWindowChrome(value: unknown): value is WindowChrome {
  if (typeof value !== "object" || value === null) return false;
  const { button_center_y, buttons_right } = value as Record<string, unknown>;
  return Number.isFinite(button_center_y) && Number.isFinite(buttons_right);
}

export function applyWindowChrome(chrome: WindowChrome | null): void {
  if (!isWindowChrome(chrome)) return;
  const { padTop, padBottom, inset } = toolbarChrome(chrome);
  const style = document.documentElement.style;
  style.setProperty("--toolbar-pad-top", `${padTop}px`);
  style.setProperty("--toolbar-pad-bottom", `${padBottom}px`);
  style.setProperty("--toolbar-inset", `${inset}px`);
}

export function watchWindowChrome(): () => void {
  let disposed = false;
  let pushed = false;
  let unlisten: (() => void) | undefined;

  invoke<WindowChrome | null>("window_chrome")
    .then((chrome) => {
      if (!disposed && !pushed) applyWindowChrome(chrome);
    })
    .catch(() => {});

  listen<WindowChrome | null>("app://window-chrome", (event) => {
    pushed = true;
    applyWindowChrome(event.payload);
  })
    .then((off) => {
      if (disposed) off();
      else unlisten = off;
    })
    .catch(() => {});

  return () => {
    disposed = true;
    unlisten?.();
  };
}
