export interface Size {
  width: number;
  height: number;
}

export interface Anchor {
  top: number;
  bottom: number;
  left: number;
}

export interface Rect {
  top: number;
  bottom: number;
  left: number;
  right: number;
}

export interface Placement {
  side: "down" | "up";
  top: number;
  left: number;
  maxHeight: number;
}

const GAP = 4;
const MARGIN = 8;

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(value, max));
}

export function placeMenu(anchor: Anchor, menu: Size, viewport: Size): Placement {
  const below = viewport.height - anchor.bottom - GAP - MARGIN;
  const above = anchor.top - GAP - MARGIN;
  const side = menu.height <= below || below >= above ? "down" : "up";
  const maxHeight = Math.max(0, side === "down" ? below : above);
  const height = Math.min(menu.height, maxHeight);
  const top = side === "down" ? anchor.bottom + GAP : anchor.top - GAP - height;
  return {
    side,
    top: clamp(top, MARGIN, viewport.height - MARGIN - height),
    left: clamp(anchor.left, MARGIN, viewport.width - MARGIN - menu.width),
    maxHeight,
  };
}

export function isWithin(inner: Rect, outer: Rect): boolean {
  return (
    inner.top >= outer.top && inner.bottom <= outer.bottom && inner.left >= outer.left && inner.right <= outer.right
  );
}
