import { fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ConnectionStatus, ProfileSummary, Transport } from "$lib/types";
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

  describe("transport picker", () => {
    function only(...transports: Transport[]) {
      return { ...profile("p1", "Office"), transports };
    }

    const toggle = () => screen.getByRole("button", { name: "Choose transport" });

    it("shows a plain Connect button for an OpenVPN-only profile", async () => {
      const onconnect = vi.fn();
      render(ProfileList, props({ profiles: [only("open_vpn")], onconnect }));
      expect(screen.queryByRole("button", { name: "Choose transport" })).toBeNull();
      await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      expect(onconnect).toHaveBeenCalledWith("p1", "open_vpn");
    });

    it("connects a WireGuard-only profile with WireGuard", async () => {
      const onconnect = vi.fn();
      render(ProfileList, props({ profiles: [only("wire_guard")], onconnect }));
      expect(screen.queryByRole("button", { name: "Choose transport" })).toBeNull();
      await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      expect(onconnect).toHaveBeenCalledWith("p1", "wire_guard");
    });

    it("leaves the transport to the daemon when the profile lists none", async () => {
      const onconnect = vi.fn();
      render(ProfileList, props({ profiles: [only()], onconnect }));
      await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      expect(onconnect).toHaveBeenCalledWith("p1", undefined);
    });

    it("connects with OpenVPN by default when WireGuard is also offered", async () => {
      const onconnect = vi.fn();
      render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")], onconnect }));
      expect(toggle()).toHaveAttribute("aria-haspopup", "menu");
      expect(toggle()).toHaveAttribute("aria-expanded", "false");
      expect(screen.queryByRole("menu")).toBeNull();

      await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      expect(onconnect).toHaveBeenCalledWith("p1", "open_vpn");
    });

    it("lists both transports and connects with the picked one without remembering it", async () => {
      const onconnect = vi.fn();
      render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")], onconnect }));

      await fireEvent.click(toggle());
      expect(toggle()).toHaveAttribute("aria-expanded", "true");
      const menu = screen.getByRole("menu");
      expect(toggle()).toHaveAttribute("aria-controls", menu.id);
      const items = screen.getAllByRole("menuitem");
      expect(items.map((item) => item.textContent)).toEqual(["OpenVPN", "WireGuard"]);
      expect(items[0]).toHaveFocus();

      await fireEvent.click(screen.getByRole("menuitem", { name: "WireGuard" }));
      expect(onconnect).toHaveBeenCalledWith("p1", "wire_guard");
      expect(screen.queryByRole("menu")).toBeNull();
      expect(toggle()).toHaveAttribute("aria-expanded", "false");

      await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      expect(onconnect).toHaveBeenLastCalledWith("p1", "open_vpn");
    });

    it("moves through the menu with the keyboard and closes on Escape", async () => {
      render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));

      await fireEvent.keyDown(toggle(), { key: "ArrowDown" });
      const [openvpn, wireguard] = screen.getAllByRole("menuitem");
      expect(openvpn).toHaveFocus();

      await fireEvent.keyDown(openvpn, { key: "ArrowDown" });
      expect(wireguard).toHaveFocus();
      await fireEvent.keyDown(wireguard, { key: "ArrowDown" });
      expect(openvpn).toHaveFocus();
      await fireEvent.keyDown(openvpn, { key: "End" });
      expect(wireguard).toHaveFocus();
      await fireEvent.keyDown(wireguard, { key: "Home" });
      expect(openvpn).toHaveFocus();

      await fireEvent.keyDown(openvpn, { key: "Escape" });
      expect(screen.queryByRole("menu")).toBeNull();
      expect(toggle()).toHaveFocus();
      expect(toggle()).toHaveAttribute("aria-expanded", "false");
    });

    it("closes on Tab and Shift+Tab without trapping focus", async () => {
      render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));

      for (const shiftKey of [false, true]) {
        await fireEvent.click(toggle());
        const [item] = screen.getAllByRole("menuitem");
        const notPrevented = await fireEvent.keyDown(item, { key: "Tab", shiftKey });
        expect(notPrevented).toBe(true);
        expect(screen.queryByRole("menu")).toBeNull();
        expect(toggle()).toHaveAttribute("aria-expanded", "false");
      }
    });

    it("stays open when the profile list refreshes with the same profiles", async () => {
      const { rerender } = render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));

      await fireEvent.click(toggle());
      const [item] = screen.getAllByRole("menuitem");
      await rerender(props({ profiles: [only("wire_guard", "open_vpn")] }));

      expect(screen.getByRole("menu")).toBeInTheDocument();
      expect(toggle()).toHaveAttribute("aria-expanded", "true");
      expect(screen.getAllByRole("menuitem")[0]).toBe(item);
    });

    describe("placement", () => {
      afterEach(() => vi.restoreAllMocks());

      function layout(buttonTop: number) {
        vi.spyOn(window, "innerHeight", "get").mockReturnValue(600);
        vi.spyOn(window, "innerWidth", "get").mockReturnValue(400);
        vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
          if (this.classList.contains("split")) return new DOMRect(16, buttonTop, 136, 28);
          if (this.classList.contains("list")) return new DOMRect(0, 40, 400, 560);
          if (this.getAttribute("role") === "menu") return new DOMRect(0, 0, 136, 72);
          return new DOMRect();
        });
      }

      it("floats below the button when there is room", async () => {
        layout(100);
        render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
        await fireEvent.click(toggle());
        const menu = screen.getByRole("menu");
        expect(menu).toHaveAttribute("data-side", "down");
        expect(menu.style.top).toBe("132px");
        expect(menu.style.left).toBe("16px");
        expect(menu.style.minWidth).toBe("136px");
      });

      it("opens upward when the button is near the bottom", async () => {
        layout(540);
        render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
        await fireEvent.click(toggle());
        const menu = screen.getByRole("menu");
        expect(menu).toHaveAttribute("data-side", "up");
        expect(menu.style.top).toBe("464px");
      });

      it("re-measures on every open", async () => {
        layout(540);
        render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
        await fireEvent.click(toggle());
        await fireEvent.keyDown(screen.getAllByRole("menuitem")[0], { key: "Escape" });

        vi.restoreAllMocks();
        layout(100);
        await fireEvent.click(toggle());
        expect(screen.getByRole("menu")).toHaveAttribute("data-side", "down");
      });

      it("follows the button when the list scrolls", async () => {
        layout(100);
        render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
        await fireEvent.click(toggle());

        vi.restoreAllMocks();
        layout(540);
        await fireEvent.scroll(screen.getByRole("list"));
        const menu = screen.getByRole("menu");
        expect(menu).toHaveAttribute("data-side", "up");
        expect(menu.style.top).toBe("464px");
      });

      it("keeps its place and scroll position when the menu itself scrolls", async () => {
        layout(100);
        render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
        await fireEvent.click(toggle());
        const menu = screen.getByRole("menu");
        menu.scrollTop = 20;

        vi.restoreAllMocks();
        layout(540);
        await fireEvent.scroll(menu);
        expect(menu).toHaveAttribute("data-side", "down");
        expect(menu.style.top).toBe("132px");
        expect(menu.scrollTop).toBe(20);
      });

      it("closes without taking focus when the list scrolls the button out of view", async () => {
        layout(100);
        render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
        await fireEvent.click(toggle());

        vi.restoreAllMocks();
        layout(20);
        await fireEvent.scroll(screen.getByRole("list"));
        expect(screen.queryByRole("menu")).toBeNull();
        expect(toggle()).toHaveAttribute("aria-expanded", "false");
        expect(toggle()).not.toHaveFocus();
      });

      it("removes its listeners when unmounted while open", async () => {
        const { unmount } = render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
        const added = [vi.spyOn(document, "addEventListener"), vi.spyOn(window, "addEventListener")];
        const removed = [vi.spyOn(document, "removeEventListener"), vi.spyOn(window, "removeEventListener")];
        await fireEvent.click(toggle());

        const watched = ["pointerdown", "scroll", "resize"];
        const listeners = added.flatMap((spy) => spy.mock.calls).filter(([type]) => watched.includes(type));
        expect(listeners.map(([type]) => type).sort()).toEqual(["pointerdown", "resize", "scroll"]);

        unmount();
        const calls = removed.flatMap((spy) => spy.mock.calls);
        for (const listener of listeners) expect(calls).toContainEqual(listener);
      });
    });

    it("overlays the list instead of taking layout space", async () => {
      const { container } = render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")] }));
      await fireEvent.click(toggle());
      const menu = screen.getByRole("menu");
      expect(getComputedStyle(menu).position).toBe("fixed");
      expect(container.querySelector(".split")).toContainElement(menu);
    });

    it("closes when clicking outside or toggling again", async () => {
      const onconnect = vi.fn();
      render(ProfileList, props({ profiles: [only("wire_guard", "open_vpn")], onconnect }));

      await fireEvent.click(toggle());
      await fireEvent.pointerDown(document.body);
      expect(screen.queryByRole("menu")).toBeNull();

      await fireEvent.click(toggle());
      await fireEvent.pointerDown(toggle());
      await fireEvent.click(toggle());
      expect(screen.queryByRole("menu")).toBeNull();
      expect(onconnect).not.toHaveBeenCalled();
    });

    it("disables the picker while another session is active", () => {
      render(
        ProfileList,
        props({
          profiles: [only("wire_guard", "open_vpn"), { ...profile("p2", "Home"), transports: ["open_vpn"] }],
          statuses: { p2: status("p2", "connected") },
        }),
      );
      expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();
      expect(toggle()).toBeDisabled();
    });

    it("replaces the picker while connecting or connected", async () => {
      const { rerender } = render(
        ProfileList,
        props({ profiles: [only("wire_guard", "open_vpn")], busy: { p1: "connect" } }),
      );
      expect(screen.queryByRole("button", { name: "Connect" })).toBeNull();
      expect(screen.queryByRole("button", { name: "Choose transport" })).toBeNull();
      expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();

      await rerender(props({ profiles: [only("wire_guard", "open_vpn")], statuses: { p1: status("p1", "connected") } }));
      expect(screen.queryByRole("button", { name: "Choose transport" })).toBeNull();
      expect(screen.getByRole("button", { name: "Disconnect" })).toBeEnabled();
    });

    it("does not reopen the menu after a connect attempt ends", async () => {
      const profiles = [only("wire_guard", "open_vpn")];
      const { rerender } = render(ProfileList, props({ profiles }));

      await fireEvent.click(toggle());
      await rerender(props({ profiles, busy: { p1: "connect" } }));
      await rerender(props({ profiles }));
      expect(screen.queryByRole("menu")).toBeNull();
      expect(toggle()).toHaveAttribute("aria-expanded", "false");
    });
  });
});
