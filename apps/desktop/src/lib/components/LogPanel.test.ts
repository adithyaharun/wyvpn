import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LogLine } from "$lib/types";

const invoke = vi.hoisted(() => vi.fn());
const copyText = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("$lib/clipboard", () => ({ copyText }));

import { daemon } from "$lib/daemon.svelte";
import { formatClock } from "$lib/format";
import LogPanel from "./LogPanel.svelte";

const markup = "<img src=x onerror=alert(1)> <b>bold</b>";

const lines: LogLine[] = [
  { seq: 0, at_ms: 1_700_000_000_000, source: "daemon", text: "Connecting" },
  { seq: 1, at_ms: 1_700_000_001_000, source: "tunnel", text: markup },
  { seq: 2, at_ms: 1_700_000_002_000, source: "daemon", text: "Connected" },
];

describe("LogPanel", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockImplementation(async (command: string) =>
      command === "session_log" ? { profile_id: "p1", lines } : null,
    );
    copyText.mockReset();
    copyText.mockResolvedValue(undefined);
  });

  it("renders markup in log lines literally", async () => {
    const { container } = render(LogPanel, { onclose: vi.fn() });
    expect(await screen.findByText(markup)).toBeInTheDocument();
    expect(container.ownerDocument.querySelector(".lines img, .lines b")).toBeNull();
  });

  it("shows a timestamp for each line", async () => {
    render(LogPanel, { onclose: vi.fn() });
    await screen.findByText("Connected");
    expect(screen.getAllByText(formatClock(lines[0].at_ms)).length).toBeGreaterThan(0);
    expect(screen.getByText(formatClock(lines[2].at_ms))).toBeInTheDocument();
  });

  it("copies every line", async () => {
    render(LogPanel, { onclose: vi.fn() });
    await screen.findByText("Connected");

    await fireEvent.click(screen.getByRole("button", { name: "Copy log" }));

    expect(copyText).toHaveBeenCalledTimes(1);
    const copied = copyText.mock.calls[0][0] as string;
    expect(copied.split("\n")).toEqual(lines.map((l) => `${formatClock(l.at_ms)} ${l.text}`));
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("disables copy while the log is empty", async () => {
    invoke.mockImplementation(async () => ({ profile_id: null, lines: [] }));
    render(LogPanel, { onclose: vi.fn() });
    expect(await screen.findByText("No log yet. Lines appear here once you connect.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy log" })).toBeDisabled();
  });

  it("asks to update the daemon when it doesn't know the log request", async () => {
    invoke.mockRejectedValue({ code: "invalid_request", message: "unknown variant `session_log`" });
    render(LogPanel, { onclose: vi.fn() });
    expect(await screen.findByRole("alert")).toHaveTextContent("Update the daemon");
  });

  it("follows new lines at the bottom and pauses after scrolling up", async () => {
    render(LogPanel, { onclose: vi.fn() });
    await screen.findByText("Connected");
    const region = screen.getByRole("region", { name: "Log lines" });
    Object.defineProperty(region, "scrollHeight", { configurable: true, value: 1000 });
    Object.defineProperty(region, "clientHeight", { configurable: true, value: 200 });

    region.scrollTop = 100;
    await fireEvent.scroll(region);
    expect(screen.getByRole("button", { name: "Show latest" })).toBeInTheDocument();

    daemon.dispatch({ type: "log", profile_id: "p1", lines: [{ seq: 3, at_ms: 1, source: "tunnel", text: "more" }] });
    await screen.findByText("more");
    expect(region.scrollTop).toBe(100);

    await fireEvent.click(screen.getByRole("button", { name: "Show latest" }));
    expect(region.scrollTop).toBe(1000);
    expect(screen.queryByRole("button", { name: "Show latest" })).toBeNull();
  });

  it("closes", async () => {
    const onclose = vi.fn();
    render(LogPanel, { onclose });
    await fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onclose).toHaveBeenCalled();
  });
});
