import { writeText } from "@tauri-apps/plugin-clipboard-manager";

export function copyText(text: string): Promise<void> {
  return writeText(text);
}
