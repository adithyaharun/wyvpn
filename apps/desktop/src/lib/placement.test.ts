import { describe, expect, it } from "vitest";
import { isWithin, placeMenu } from "./placement";

const viewport = { width: 400, height: 600 };
const menu = { width: 140, height: 80 };
const tall = { width: 140, height: 500 };

describe("placeMenu", () => {
  it("opens below the button when there is room", () => {
    expect(placeMenu({ top: 100, bottom: 128, left: 16 }, menu, viewport)).toEqual({
      side: "down",
      top: 132,
      left: 16,
      maxHeight: 460,
    });
  });

  it("opens above the button when it is near the bottom", () => {
    expect(placeMenu({ top: 540, bottom: 568, left: 16 }, menu, viewport)).toEqual({
      side: "up",
      top: 456,
      left: 16,
      maxHeight: 528,
    });
  });

  it("takes the roomier side below and scrolls when neither side fits", () => {
    expect(placeMenu({ top: 200, bottom: 228, left: 16 }, tall, viewport)).toEqual({
      side: "down",
      top: 232,
      left: 16,
      maxHeight: 360,
    });
  });

  it("takes the roomier side above and stays inside the viewport", () => {
    expect(placeMenu({ top: 380, bottom: 408, left: 16 }, tall, viewport)).toEqual({
      side: "up",
      top: 8,
      left: 16,
      maxHeight: 368,
    });
  });

  it("keeps the menu inside the left and right edges", () => {
    expect(placeMenu({ top: 100, bottom: 128, left: 330 }, menu, viewport).left).toBe(252);
    expect(placeMenu({ top: 100, bottom: 128, left: -20 }, menu, viewport).left).toBe(8);
  });
});

describe("isWithin", () => {
  const list = { top: 50, bottom: 550, left: 0, right: 400 };

  it("accepts a box fully inside, edges included", () => {
    expect(isWithin({ top: 50, bottom: 78, left: 16, right: 152 }, list)).toBe(true);
    expect(isWithin({ top: 522, bottom: 550, left: 0, right: 400 }, list)).toBe(true);
  });

  it("rejects a box partly or fully scrolled out", () => {
    expect(isWithin({ top: 40, bottom: 68, left: 16, right: 152 }, list)).toBe(false);
    expect(isWithin({ top: 540, bottom: 568, left: 16, right: 152 }, list)).toBe(false);
    expect(isWithin({ top: -100, bottom: -72, left: 16, right: 152 }, list)).toBe(false);
  });
});
