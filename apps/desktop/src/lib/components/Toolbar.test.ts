import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

const startDragging = vi.hoisted(() => vi.fn(async () => {}));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (command: string) => (command === "plugin:window|start_dragging" ? startDragging() : Promise.resolve()),
}));

import Toolbar from "./Toolbar.svelte";

function props(overrides: Partial<{ available: boolean }> = {}) {
  return { available: true, onimport: vi.fn(), onlog: vi.fn(), onsettings: vi.fn(), ...overrides };
}

describe("Toolbar", () => {
  beforeEach(() => startDragging.mockClear());

  it("shows the app name and labelled icon buttons", () => {
    render(Toolbar, props());
    expect(screen.getByText("WyVPN")).toBeInTheDocument();
    for (const name of ["Import profile", "Connection log", "Settings"]) {
      const button = screen.getByRole("button", { name });
      expect(button).toHaveAttribute("title", name);
      expect(button.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    }
  });

  it("runs each action", async () => {
    const handlers = props();
    render(Toolbar, handlers);
    await fireEvent.click(screen.getByRole("button", { name: "Import profile" }));
    await fireEvent.click(screen.getByRole("button", { name: "Connection log" }));
    await fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(handlers.onimport).toHaveBeenCalledOnce();
    expect(handlers.onlog).toHaveBeenCalledOnce();
    expect(handlers.onsettings).toHaveBeenCalledOnce();
  });

  it("disables the log and import while the service is unavailable", () => {
    render(Toolbar, props({ available: false }));
    expect(screen.getByRole("button", { name: "Connection log" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Import profile" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Settings" })).toBeEnabled();
  });

  it("drags the window from the toolbar but not from its buttons", async () => {
    const { container } = render(Toolbar, props());
    const toolbar = container.querySelector("header")!;
    expect(toolbar).toHaveAttribute("data-tauri-drag-region");

    await fireEvent.mouseDown(toolbar, { button: 0 });
    await fireEvent.mouseDown(screen.getByText("WyVPN"), { button: 0 });
    expect(startDragging).toHaveBeenCalledTimes(2);

    await fireEvent.mouseDown(toolbar, { button: 2 });
    const settings = screen.getByRole("button", { name: "Settings" });
    await fireEvent.mouseDown(settings, { button: 0 });
    await fireEvent.mouseDown(settings.querySelector("svg")!, { button: 0 });
    expect(startDragging).toHaveBeenCalledTimes(2);
  });

  it("ignores a failed drag", async () => {
    startDragging.mockRejectedValueOnce(new Error("not allowed"));
    const { container } = render(Toolbar, props());
    await fireEvent.mouseDown(container.querySelector("header")!, { button: 0 });
    expect(startDragging).toHaveBeenCalledOnce();
  });
});
