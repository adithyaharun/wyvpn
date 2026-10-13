import { fireEvent, render, screen } from "@testing-library/svelte";
import { createRawSnippet } from "svelte";
import { afterEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn(async () => null));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { toasts } from "$lib/toast.svelte";
import Layout from "./+layout.svelte";

describe("layout error boundary", () => {
  afterEach(() => toasts.clear());

  it("reports a view that fails to render and offers a retry", async () => {
    let broken = true;
    const children = createRawSnippet(() => ({
      render: () => {
        if (broken) throw new Error("view broke");
        return "<p>Recovered</p>";
      },
    }));
    render(Layout, { children });

    expect(await screen.findByRole("alert")).toHaveTextContent("view broke");
    expect(screen.getByText("This view couldn't be shown.")).toBeInTheDocument();

    broken = false;
    await fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Recovered")).toBeInTheDocument();
  });
});
