import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import LicensesPanel from "./LicensesPanel.svelte";

function backend(notice: { license: string; source_url: string | null }, text = "Apache-2.0 text") {
  invoke.mockImplementation(async (command: string) => {
    if (command === "third_party_licenses") return text;
    if (command === "openvpn_notice") return notice;
    return null;
  });
}

describe("LicensesPanel", () => {
  beforeEach(() => invoke.mockReset());

  it("shows the license text and the OpenVPN source link", async () => {
    backend({ license: "GPL-2.0", source_url: "https://example.com/releases/tag/v1" });
    render(LicensesPanel, { onclose: () => {} });

    expect(await screen.findByText("Apache-2.0 text")).toBeInTheDocument();
    expect(await screen.findByText(/OpenVPN is licensed under GPL-2.0/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "https://example.com/releases/tag/v1" }));
    expect(invoke).toHaveBeenCalledWith("open_support", { target: "openvpn_source" });
  });

  it("mentions the distribution package on Linux", async () => {
    backend({ license: "GPL-2.0", source_url: null });
    render(LicensesPanel, { onclose: () => {} });

    expect(await screen.findByText(/uses your distribution's OpenVPN package/)).toBeInTheDocument();
  });

  it("shows the fallback text from the backend", async () => {
    backend({ license: "GPL-2.0", source_url: null }, "Third-party license text is not available in this build.");
    render(LicensesPanel, { onclose: () => {} });

    expect(await screen.findByText(/not available in this build/)).toBeInTheDocument();
  });
});
