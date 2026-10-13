import { fireEvent, render, screen } from "@testing-library/svelte";
import { describe, expect, it, vi } from "vitest";
import type { ConnectionStatus, ProfileSummary } from "$lib/types";
import ProfileList from "./ProfileList.svelte";
import StatusPanel from "./StatusPanel.svelte";

const markup = "<img src=x onerror=alert(1)>";

function profile(id: string, name: string): ProfileSummary {
  return {
    id,
    name,
    server_name: "gw",
    server_host: "vpn.example.com",
    user: "alice",
    auth_mode: "pin",
    transports: ["wire_guard", "open_vpn"],
  };
}

function status(profileId: string, state: ConnectionStatus["state"]): ConnectionStatus {
  return {
    profile_id: profileId,
    profile_name: markup,
    state,
    transport: "wire_guard",
    tunnel_ip: "10.0.0.2",
    server_endpoint: "vpn.example.com:51820",
    connected_since: null,
    rx_bytes: 1_500,
    tx_bytes: 0,
    error: null,
  };
}

function props(overrides: Partial<Parameters<typeof ProfileList>[1]> = {}) {
  return {
    profiles: [profile("p1", markup)],
    statuses: {},
    busy: {},
    available: true,
    onconnect: vi.fn(),
    ondisconnect: vi.fn(),
    onremove: vi.fn(),
    onrename: vi.fn(async () => undefined),
    onimport: vi.fn(),
    ...overrides,
  };
}

describe("ProfileList", () => {
  it("renders markup in profile names as text", () => {
    const { container } = render(ProfileList, props());
    expect(screen.getByText(markup)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("alice on vpn.example.com")).toBeInTheDocument();
    expect(screen.getByText("WireGuard, OpenVPN")).toBeInTheDocument();
  });

  it("renders markup in the status panel as text", () => {
    const { container } = render(StatusPanel, { session: status("p1", "connected") });
    expect(screen.getByText(markup, { exact: false })).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("1.5 KB")).toBeInTheDocument();
  });

  it("labels the local end of the tunnel as this device", () => {
    render(StatusPanel, { session: status("p1", "connected") });
    expect(screen.getByText("This device")).toBeInTheDocument();
    expect(screen.queryByText("This Mac")).toBeNull();
  });

  it("leads to import when empty", async () => {
    const onimport = vi.fn();
    render(ProfileList, props({ profiles: [], onimport }));
    expect(screen.getByText("No profiles yet")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Import profile" }));
    expect(onimport).toHaveBeenCalled();
  });

  it("separates each profile row with a divider", () => {
    const { container } = render(
      ProfileList,
      props({ profiles: [profile("p1", "Office"), profile("p2", "Home"), profile("p3", "Lab")] }),
    );
    const rows = [...container.querySelectorAll("li")];
    expect(rows).toHaveLength(3);
    expect(rows[0]).not.toHaveClass("divided");
    expect(rows[1]).toHaveClass("divided");
    expect(rows[2]).toHaveClass("divided");
  });

  it("leaves importing to the toolbar once profiles exist", () => {
    render(ProfileList, props({ profiles: [profile("p1", "Office")] }));
    expect(screen.queryByRole("button", { name: /import/i })).toBeNull();
  });

  it("names icon-only row actions and shows them as tooltips", () => {
    render(ProfileList, props({ profiles: [profile("p1", "Office")] }));
    for (const name of ["Rename", "Remove"]) {
      const button = screen.getByRole("button", { name });
      expect(button).toHaveAttribute("title", name);
      expect(button).toHaveTextContent("");
    }
    expect(screen.getByRole("button", { name: "Connect" })).toHaveTextContent("Connect");
  });

  it("disables connect while another session is active", () => {
    render(
      ProfileList,
      props({
        profiles: [profile("p1", "Office"), profile("p2", "Home")],
        statuses: { p2: status("p2", "connected") },
      }),
    );
    expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Disconnect" })).toBeEnabled();
  });

  it("disables every action when the daemon is unavailable", () => {
    render(ProfileList, props({ available: false, profiles: [profile("p1", "Office")] }));
    for (const button of screen.getAllByRole("button")) expect(button).toBeDisabled();
  });

  it("asks for confirmation before removing", async () => {
    const onremove = vi.fn();
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onremove }));

    await fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(onremove).not.toHaveBeenCalled();
    expect(screen.getByText("Remove this profile?")).toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(onremove).toHaveBeenCalledWith("p1");
  });

  it("saves a new name on Enter", async () => {
    const onrename = vi.fn(async () => undefined);
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    const input = screen.getByLabelText<HTMLInputElement>("Profile name");
    expect(input).toHaveFocus();
    expect(input.value).toBe("Office");

    await fireEvent.input(input, { target: { value: "  Work  " } });
    await fireEvent.keyDown(input, { key: "Enter" });

    expect(onrename).toHaveBeenCalledWith("p1", "Work");
    await vi.waitFor(() => expect(screen.queryByLabelText("Profile name")).toBeNull());
    expect(screen.getByRole("button", { name: "Rename" })).toHaveFocus();
  });

  it("shows the new name when the list updates", async () => {
    const { rerender } = render(ProfileList, props({ profiles: [profile("p1", "Office")] }));
    await rerender(props({ profiles: [{ ...profile("p1", "Work"), imported_name: "Office" }] }));
    expect(screen.getByRole("heading", { name: "Work" })).toBeInTheDocument();
  });

  it("cancels on Escape without saving", async () => {
    const onrename = vi.fn(async () => undefined);
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    const input = screen.getByLabelText("Profile name");
    await fireEvent.input(input, { target: { value: "Work" } });
    await fireEvent.keyDown(input, { key: "Escape" });

    expect(onrename).not.toHaveBeenCalled();
    expect(screen.queryByLabelText("Profile name")).toBeNull();
    expect(screen.getByRole("heading", { name: "Office" })).toBeInTheDocument();
  });

  it("resets to the imported name when the value is cleared", async () => {
    const onrename = vi.fn(async () => undefined);
    render(ProfileList, props({ profiles: [{ ...profile("p1", "Work"), imported_name: "Office" }], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    const input = screen.getByLabelText("Profile name");
    await fireEvent.input(input, { target: { value: "" } });
    expect(screen.getByText("Reset to Office")).toBeInTheDocument();

    await fireEvent.keyDown(input, { key: "Enter" });
    expect(onrename).toHaveBeenCalledWith("p1", "");
  });

  it("closes without saving when an unrenamed profile is cleared", async () => {
    const onrename = vi.fn(async () => undefined);
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    const input = screen.getByLabelText("Profile name");
    await fireEvent.input(input, { target: { value: " " } });
    await fireEvent.keyDown(input, { key: "Enter" });

    expect(onrename).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(screen.queryByLabelText("Profile name")).toBeNull());
  });

  it("keeps editing and shows the daemon's reason when a name is rejected", async () => {
    const onrename = vi.fn(async () => {
      throw { code: "invalid_request", message: "name must not contain control characters" };
    });
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    await fireEvent.input(screen.getByLabelText("Profile name"), { target: { value: "Work" } });
    await fireEvent.keyDown(screen.getByLabelText("Profile name"), { key: "Enter" });

    expect(await screen.findByRole("alert")).toHaveTextContent("name must not contain control characters");
    expect(screen.getByLabelText("Profile name")).toBeInTheDocument();
  });

  it("asks to update the daemon when it doesn't know rename", async () => {
    const onrename = vi.fn(async () => {
      throw { code: "invalid_request", message: "unknown variant `rename_profile`, expected one of `connect`" };
    });
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    await fireEvent.input(screen.getByLabelText("Profile name"), { target: { value: "Work" } });
    await fireEvent.keyDown(screen.getByLabelText("Profile name"), { key: "Enter" });

    expect(await screen.findByRole("alert")).toHaveTextContent("Update the daemon");
  });

  it("counts emoji as one character each toward the name limit", async () => {
    const onrename = vi.fn(async () => undefined);
    const name = "😀".repeat(40);
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    const input = screen.getByLabelText("Profile name");
    expect(input).not.toHaveAttribute("maxlength");
    await fireEvent.input(input, { target: { value: name } });
    expect(screen.queryByRole("alert")).toBeNull();
    await fireEvent.keyDown(input, { key: "Enter" });

    expect(onrename).toHaveBeenCalledWith("p1", name);
  });

  it("blocks saving a name over 64 characters", async () => {
    const onrename = vi.fn(async () => undefined);
    render(ProfileList, props({ profiles: [profile("p1", "Office")], onrename }));

    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    const input = screen.getByLabelText("Profile name");
    await fireEvent.input(input, { target: { value: "😀".repeat(65) } });

    expect(screen.getByRole("alert")).toHaveTextContent("Use 64 characters or fewer.");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    await fireEvent.keyDown(input, { key: "Enter" });
    expect(onrename).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Profile name")).toBeInTheDocument();

    await fireEvent.input(input, { target: { value: ` ${"😀".repeat(64)} ` } });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });

  it("shows the tunnel IP on the connected row only", () => {
    render(
      ProfileList,
      props({
        profiles: [profile("p1", "Office"), profile("p2", "Home")],
        statuses: { p1: status("p1", "connected"), p2: { ...status("p2", "disconnected"), tunnel_ip: "10.9.9.9" } },
      }),
    );
    expect(screen.getByText("10.0.0.2")).toBeInTheDocument();
    expect(screen.queryByText("10.9.9.9")).toBeNull();
  });
});
