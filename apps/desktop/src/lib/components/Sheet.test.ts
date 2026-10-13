import { fireEvent, render } from "@testing-library/svelte";
import { createRawSnippet } from "svelte";
import { describe, expect, it, vi } from "vitest";
import Sheet from "./Sheet.svelte";

const children = createRawSnippet(() => ({ render: () => "<p>Body</p>" }));

function scrim(container: HTMLElement): Element {
  const element = container.ownerDocument.querySelector(".scrim");
  if (!element) throw new Error("no backdrop");
  return element;
}

describe("Sheet backdrop", () => {
  it("closes on a backdrop click by default", async () => {
    const onclose = vi.fn();
    const { container } = render(Sheet, { title: "Test", onclose, children });
    await fireEvent.click(scrim(container));
    expect(onclose).toHaveBeenCalledOnce();
  });

  it("stays open on a backdrop click when turned off", async () => {
    const onclose = vi.fn();
    const { container } = render(Sheet, { title: "Test", closeOnBackdrop: false, onclose, children });
    await fireEvent.click(scrim(container));
    expect(onclose).not.toHaveBeenCalled();
    expect(scrim(container)).toHaveAttribute("data-tauri-drag-region");
  });
});
