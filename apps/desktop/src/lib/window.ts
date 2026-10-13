import { invoke } from "@tauri-apps/api/core";

const INTERACTIVE = "button, input, select, textarea, a, [role='button']";

export function startWindowDrag(): void {
  invoke("plugin:window|start_dragging", { label: "main" }).catch(() => {});
}

export function dragWindow(event: MouseEvent): void {
  if (event.button !== 0) return;
  if (event.target instanceof Element && event.target.closest(INTERACTIVE)) return;
  startWindowDrag();
}
