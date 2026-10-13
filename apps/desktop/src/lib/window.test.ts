import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
const unlisten = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return unlisten;
  }),
}));

import { applyWindowChrome, toolbarChrome, watchWindowChrome } from "./window";

const VARS = ["--toolbar-pad-top", "--toolbar-pad-bottom", "--toolbar-inset"];

function vars() {
  const style = document.documentElement.style;
  return Object.fromEntries(VARS.map((name) => [name, style.getPropertyValue(name)]));
}

function clearVars() {
  for (const name of VARS) document.documentElement.style.removeProperty(name);
}

describe("toolbarChrome", () => {
  it("lifts the content for old-style buttons", () => {
    expect(toolbarChrome({ button_center_y: 17, buttons_right: 70 })).toEqual({
      padTop: 0,
      padBottom: 6,
      inset: 86,
    });
  });

  it("lowers the content for new-style buttons", () => {
    expect(toolbarChrome({ button_center_y: 23.5, buttons_right: 78.4 })).toEqual({
      padTop: 7,
      padBottom: 0,
      inset: 94,
    });
  });

  it("adds no padding when the buttons sit at the toolbar centre", () => {
    expect(toolbarChrome({ button_center_y: 20, buttons_right: 70 })).toMatchObject({ padTop: 0, padBottom: 0 });
  });

  it("keeps room for the 28px icon buttons", () => {
    expect(toolbarChrome({ button_center_y: 400, buttons_right: 70 })).toMatchObject({ padTop: 12, padBottom: 0 });
    expect(toolbarChrome({ button_center_y: -5, buttons_right: 70 })).toMatchObject({ padTop: 0, padBottom: 12 });
    expect(toolbarChrome({ button_center_y: 20, buttons_right: -30 }).inset).toBe(16);
  });

  it("centres the content box on the buttons for another toolbar height", () => {
    const { padTop, padBottom } = toolbarChrome({ button_center_y: 26, buttons_right: 70 }, 48);
    expect(padTop + (48 - padTop - padBottom) / 2).toBe(26);
  });
});

describe("applyWindowChrome", () => {
  beforeEach(clearVars);
  afterEach(clearVars);

  it("sets the toolbar padding and inset on the root element", () => {
    applyWindowChrome({ button_center_y: 23.5, buttons_right: 70 });
    expect(vars()).toEqual({
      "--toolbar-pad-top": "7px",
      "--toolbar-pad-bottom": "0px",
      "--toolbar-inset": "86px",
    });
  });

  it("leaves the variables unset without chrome", () => {
    applyWindowChrome(null);
    applyWindowChrome({ button_center_y: Number.NaN, buttons_right: 70 });
    expect(vars()).toEqual({ "--toolbar-pad-top": "", "--toolbar-pad-bottom": "", "--toolbar-inset": "" });
  });
});

describe("watchWindowChrome", () => {
  beforeEach(() => {
    clearVars();
    handlers.clear();
    invoke.mockReset();
    unlisten.mockReset();
  });
  afterEach(clearVars);

  it("applies the queried chrome and later pushes", async () => {
    invoke.mockResolvedValue({ button_center_y: 17, buttons_right: 70 });
    const stop = watchWindowChrome();

    await vi.waitFor(() => expect(vars()["--toolbar-pad-bottom"]).toBe("6px"));
    expect(invoke).toHaveBeenCalledWith("window_chrome");

    await vi.waitFor(() => expect(handlers.has("app://window-chrome")).toBe(true));
    handlers.get("app://window-chrome")?.({ payload: { button_center_y: 23.5, buttons_right: 80 } });
    expect(vars()).toEqual({
      "--toolbar-pad-top": "7px",
      "--toolbar-pad-bottom": "0px",
      "--toolbar-inset": "96px",
    });

    stop();
    expect(unlisten).toHaveBeenCalled();
  });

  it("swallows a failed query", async () => {
    invoke.mockRejectedValue(new Error("unknown command"));
    const stop = watchWindowChrome();

    await vi.waitFor(() => expect(handlers.has("app://window-chrome")).toBe(true));
    expect(vars()["--toolbar-inset"]).toBe("");
    stop();
  });
});
