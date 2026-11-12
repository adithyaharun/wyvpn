import { api } from "./api";
import type { UpdatePrompt, WindowRequest } from "./types";

export interface WindowRequestHandlers {
  licenses(): void;
  updatePrompt(prompt: UpdatePrompt): void;
}

export async function drainWindowRequests(handlers: WindowRequestHandlers): Promise<void> {
  let requests: WindowRequest[];
  try {
    requests = await api.takeWindowRequests();
  } catch {
    return;
  }
  if (!Array.isArray(requests)) return;
  for (const request of requests) {
    switch (request?.kind) {
      case "licenses":
        handlers.licenses();
        break;
      case "update_prompt":
        handlers.updatePrompt({ outcome: request.outcome });
        break;
    }
  }
}
