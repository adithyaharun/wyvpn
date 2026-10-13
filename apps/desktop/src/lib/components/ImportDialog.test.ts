import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { daemon } from "$lib/daemon.svelte";
import ImportDialog from "./ImportDialog.svelte";

const office = {
  id: "p1",
  name: "Office",
  server_name: "gw",
  server_host: "vpn.example.com",
  user: "alice",
  auth_mode: "pin",
  transports: ["wire_guard"],
};

describe("ImportDialog", () => {
  beforeEach(() => {
    invoke.mockReset();
    daemon.dispatch({ type: "profiles", profiles: [] });
    daemon.dispatch({ type: "availability", available: false, socket: "" });
    invoke.mockResolvedValue([]);
    daemon.dispatch({ type: "availability", available: true, socket: "/tmp/w.sock" });
  });

  it("offers to replace a duplicate link import and retries with replace", async () => {
    invoke.mockImplementation(async (command: string, args?: { replace?: boolean }) => {
      if (command === "import_link" && !args?.replace) {
        throw { code: "already_exists", message: "profile Office already exists; use replace to overwrite" };
      }
      if (command === "import_link") return [office];
      return [];
    });
    render(ImportDialog, { onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("Or paste a profile link"), {
      target: { value: "https://vpn.example.com/link" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));

    const replace = await screen.findByRole("button", { name: "Replace" });
    expect(screen.getByText(/is already imported/)).toHaveTextContent(
      "Office is already imported. Replace it with the new copy?",
    );
    await fireEvent.click(replace);

    expect(await screen.findByText("Imported Office")).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("import_link", {
      link: "https://vpn.example.com/link",
      replace: true,
    });
    expect(invoke).not.toHaveBeenCalledWith("replace_import", expect.anything());
  });

  it("replaces a duplicate file import with the retry token instead of a new picker", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "import_file") {
        throw {
          code: "already_exists",
          message: "profile Office already exists; use replace to overwrite",
          retry: "tok-1",
        };
      }
      if (command === "replace_import") return [office];
      return [];
    });
    render(ImportDialog, { onclose: vi.fn() });

    await fireEvent.click(screen.getByRole("button", { name: "Choose file…" }));
    const replace = await screen.findByRole("button", { name: "Replace" });
    expect(screen.queryByText(/choose the file again/i)).toBeNull();
    await fireEvent.click(replace);

    expect(await screen.findByText("Imported Office")).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("replace_import", { retry: "tok-1" });
    expect(invoke.mock.calls.filter(([command]) => command === "import_file")).toHaveLength(1);
  });

  it("lets the user choose again when the replace token expired", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "import_file") {
        throw { code: "already_exists", message: "profile Office already exists; use replace to overwrite", retry: "old" };
      }
      if (command === "replace_import") {
        throw { code: "invalid_request", message: "the import expired; choose the file again" };
      }
      return [];
    });
    render(ImportDialog, { onclose: vi.fn() });

    await fireEvent.click(screen.getByRole("button", { name: "Choose file…" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Replace" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("the import expired; choose the file again");
    expect(screen.getByRole("button", { name: "Choose file…" })).toBeEnabled();
  });

  it("shows other errors without offering to replace", async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === "import_file") {
        throw { code: "invalid_state", message: "profile Office already exists twice in this import" };
      }
      return [];
    });
    render(ImportDialog, { onclose: vi.fn() });

    await fireEvent.click(screen.getByRole("button", { name: "Choose file…" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("profile Office already exists twice in this import");
    expect(screen.queryByRole("button", { name: "Replace" })).toBeNull();
  });

  it("returns to the start when the file picker is cancelled", async () => {
    invoke.mockImplementation(async (command: string) => (command === "import_file" ? null : []));
    render(ImportDialog, { onclose: vi.fn() });

    await fireEvent.click(screen.getByRole("button", { name: "Choose file…" }));
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("import_file", { replace: false }));
    expect(await screen.findByRole("button", { name: "Choose file…" })).toBeEnabled();
  });
});
