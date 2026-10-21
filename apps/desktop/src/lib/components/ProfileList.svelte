<script lang="ts">
  import ChevronDown from "@lucide/svelte/icons/chevron-down";
  import FilePlus from "@lucide/svelte/icons/file-plus";
  import LoaderCircle from "@lucide/svelte/icons/loader-circle";
  import Pencil from "@lucide/svelte/icons/pencil";
  import Plug from "@lucide/svelte/icons/plug";
  import Trash2 from "@lucide/svelte/icons/trash-2";
  import Unplug from "@lucide/svelte/icons/unplug";
  import { tick } from "svelte";
  import type { Attachment } from "svelte/attachments";
  import { describeRenameError, toCommandError } from "$lib/errors";
  import { transportLabel } from "$lib/format";
  import { isWithin, placeMenu } from "$lib/placement";
  import { isActive } from "$lib/reducer";
  import { defaultTransport, transportChoices } from "$lib/transport";
  import type { BusyAction, ConnectionStatus, ProfileSummary, Transport } from "$lib/types";

  interface Props {
    profiles: ProfileSummary[];
    statuses: Record<string, ConnectionStatus>;
    busy: Record<string, BusyAction>;
    available: boolean;
    onconnect: (profileId: string, transport?: Transport) => void;
    ondisconnect: (profileId: string) => void;
    onremove: (profileId: string) => void;
    onrename: (profileId: string, name: string) => Promise<unknown>;
    onimport: () => void;
  }

  let {
    profiles,
    statuses,
    busy,
    available,
    onconnect,
    ondisconnect,
    onremove,
    onrename,
    onimport,
  }: Props = $props();

  const NAME_LIMIT = 64;

  const uid = $props.id();
  let confirming = $state<string | null>(null);
  let editing = $state<string | null>(null);
  let draft = $state("");
  let saving = $state(false);
  let renameError = $state<string | null>(null);
  const renameButtons: Record<string, HTMLButtonElement | undefined> = {};
  let menuFor = $state<string | null>(null);
  const menuToggles: Record<string, HTMLButtonElement | undefined> = {};
  let nameInput = $state<HTMLInputElement>();
  // The daemon counts Unicode scalar values, not UTF-16 units as maxlength does.
  const tooLong = $derived([...draft.trim()].length > NAME_LIMIT);

  const selectAll: Attachment<HTMLInputElement> = (node) => {
    node.focus();
    node.select();
  };

  function startRename(profile: ProfileSummary) {
    confirming = null;
    renameError = null;
    draft = profile.name;
    editing = profile.id;
  }

  async function stopRename(profileId: string) {
    editing = null;
    renameError = null;
    saving = false;
    await tick();
    renameButtons[profileId]?.focus();
  }

  async function saveRename(profile: ProfileSummary) {
    if (saving || tooLong) return;
    const name = draft.trim();
    if (name === profile.name || (!name && !profile.imported_name)) {
      await stopRename(profile.id);
      return;
    }
    saving = true;
    renameError = null;
    try {
      await onrename(profile.id, name);
      await stopRename(profile.id);
    } catch (error) {
      saving = false;
      renameError = describeRenameError(toCommandError(error).toBody());
      await tick();
      nameInput?.focus();
    }
  }

  function onRenameKey(event: KeyboardEvent, profile: ProfileSummary) {
    if (event.key === "Enter") {
      event.preventDefault();
      void saveRename(profile);
    } else if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      void stopRename(profile.id);
    }
  }

  const activeId = $derived(
    Object.values(statuses).find((status) => isActive(status.state))?.profile_id ?? null,
  );

  function closeMenu(profileId: string, refocus: boolean) {
    if (menuFor !== profileId) return;
    menuFor = null;
    if (refocus) menuToggles[profileId]?.focus();
  }

  function pickTransport(profileId: string, transport: Transport) {
    menuFor = null;
    onconnect(profileId, transport);
  }

  function onToggleKey(event: KeyboardEvent, profileId: string) {
    if (event.key !== "ArrowDown") return;
    event.preventDefault();
    menuFor = profileId;
  }

  function onMenuKey(event: KeyboardEvent, profileId: string) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeMenu(profileId, true);
      return;
    }
    if (event.key === "Tab") {
      closeMenu(profileId, false);
      return;
    }
    const items = [...(event.currentTarget as HTMLElement).querySelectorAll<HTMLElement>('[role="menuitem"]')];
    const current = items.indexOf(document.activeElement as HTMLElement);
    const last = items.length - 1;
    const targets: Record<string, number> = {
      ArrowDown: current >= last ? 0 : current + 1,
      ArrowUp: current <= 0 ? last : current - 1,
      Home: 0,
      End: last,
    };
    const next = targets[event.key];
    if (next === undefined) return;
    event.preventDefault();
    items[next]?.focus({ preventScroll: true });
  }

  function onSplitFocusOut(event: FocusEvent, profileId: string) {
    const next = event.relatedTarget;
    if (next instanceof Node && !(event.currentTarget as HTMLElement).contains(next)) closeMenu(profileId, false);
  }

  const transportMenu =
    (profileId: string): Attachment<HTMLElement> =>
    (node) => {
      const anchor = node.parentElement;
      const place = () => {
        if (!anchor) return;
        const box = anchor.getBoundingClientRect();
        node.style.minWidth = `${box.width}px`;
        node.style.maxHeight = "";
        const { side, top, left, maxHeight } = placeMenu(box, node.getBoundingClientRect(), {
          width: window.innerWidth,
          height: window.innerHeight,
        });
        node.dataset.side = side;
        node.style.top = `${top}px`;
        node.style.left = `${left}px`;
        node.style.maxHeight = `${maxHeight}px`;
      };
      const list = node.closest<HTMLElement>(".list");
      const follow = (event: Event) => {
        if (event.target instanceof Node && node.contains(event.target)) return;
        if (anchor && list && !isWithin(anchor.getBoundingClientRect(), list.getBoundingClientRect())) {
          closeMenu(profileId, false);
          return;
        }
        place();
      };
      place();
      node.querySelector<HTMLElement>('[role="menuitem"]')?.focus({ preventScroll: true });
      const onPointerDown = (event: PointerEvent) => {
        if (!anchor?.contains(event.target as Node)) closeMenu(profileId, false);
      };
      document.addEventListener("pointerdown", onPointerDown);
      document.addEventListener("scroll", follow, true);
      window.addEventListener("resize", follow);
      return () => {
        document.removeEventListener("pointerdown", onPointerDown);
        document.removeEventListener("scroll", follow, true);
        window.removeEventListener("resize", follow);
        if (menuFor === profileId) menuFor = null;
      };
    };

  function confirmRemove(profileId: string) {
    confirming = null;
    onremove(profileId);
  }
</script>

<section class="profiles" aria-labelledby="profiles-title">
  <header>
    <h2 id="profiles-title">Profiles</h2>
  </header>

  {#if profiles.length === 0}
    {#if available}
      <div class="empty">
        <h3>No profiles yet</h3>
        <p>Import a profile file or paste a profile link from your VPN server.</p>
        <button class="btn btn-primary" type="button" onclick={onimport}>
          <FilePlus size={16} strokeWidth={1.75} aria-hidden="true" />
          Import profile
        </button>
      </div>
    {:else}
      <p class="note">Profiles load once the service is running.</p>
    {/if}
  {:else}
    <ul class="list">
      {#each profiles as profile, index (profile.id)}
        {@const state = statuses[profile.id]?.state ?? "disconnected"}
        {@const action = busy[profile.id]}
        {@const otherActive = activeId !== null && activeId !== profile.id}
        {@const locked = !available || action !== undefined}
        {@const tunnelIp = state === "connected" ? statuses[profile.id]?.tunnel_ip : null}
        <li class="row" class:divided={index > 0} class:connected={state === "connected"}>
          <div class="info">
            {#if editing === profile.id}
              {@const hintId = `${uid}-${profile.id}-hint`}
              <label class="sr-only" for="{uid}-{profile.id}-name">Profile name</label>
              <input
                id="{uid}-{profile.id}-name"
                class="field name-field"
                type="text"
                autocomplete="off"
                spellcheck="false"
                aria-describedby={hintId}
                aria-invalid={renameError !== null || tooLong}
                disabled={saving}
                bind:value={draft}
                bind:this={nameInput}
                onkeydown={(event) => onRenameKey(event, profile)}
                {@attach selectAll}
              />
              <p class="hint" id={hintId}>
                {#if renameError}
                  <span class="alert" role="alert">{renameError}</span>
                {:else if tooLong}
                  <span class="alert" role="alert">Use {NAME_LIMIT} characters or fewer.</span>
                {:else if !draft.trim() && profile.imported_name}
                  Reset to {profile.imported_name}
                {:else}
                  Press Enter to save or Escape to cancel.
                {/if}
              </p>
            {:else}
              <h3 class="name">{profile.name}</h3>
            {/if}
            <p class="meta selectable">
              {profile.user ? `${profile.user} on ${profile.server_host}` : profile.server_host}
            </p>
            {#if profile.transports.length > 0 || tunnelIp}
              <p class="transports">
                <span>{profile.transports.map(transportLabel).join(", ")}</span>
                {#if tunnelIp}
                  <span class="tunnel"><span class="tunnel-label">Tunnel IP</span> <span class="num selectable">{tunnelIp}</span></span>
                {/if}
              </p>
            {/if}
          </div>

          <div class="actions">
            {#if editing === profile.id}
              <button
                class="btn btn-primary"
                type="button"
                disabled={!available || saving || tooLong}
                onclick={() => saveRename(profile)}>{saving ? "Saving…" : "Save"}</button
              >
              <button class="btn btn-text" type="button" onclick={() => stopRename(profile.id)}>Cancel</button>
            {:else if confirming === profile.id}
              <span class="confirm-text">Remove this profile?</span>
              <button
                class="btn btn-danger-fill"
                type="button"
                disabled={locked}
                onclick={() => confirmRemove(profile.id)}>Remove</button
              >
              <button class="btn btn-text" type="button" onclick={() => (confirming = null)}>Keep</button>
            {:else}
              {@const phase =
                state === "connected"
                  ? "connected"
                  : state === "connecting" || action === "connect"
                    ? "connecting"
                    : state === "disconnecting" || action === "disconnect"
                      ? "disconnecting"
                      : "idle"}
              {#if phase === "connected"}
                <button class="btn btn-secondary main" type="button" disabled={locked} onclick={() => ondisconnect(profile.id)}>
                  <Unplug size={16} strokeWidth={1.75} aria-hidden="true" />
                  Disconnect
                </button>
              {:else if phase === "connecting"}
                <button
                  class="btn btn-secondary main"
                  type="button"
                  title="Stop connecting"
                  disabled={!available || action === "disconnect"}
                  onclick={() => ondisconnect(profile.id)}
                >
                  <LoaderCircle class="spin" size={16} strokeWidth={1.75} aria-hidden="true" />
                  Cancel
                </button>
              {:else if phase === "disconnecting"}
                <button class="btn btn-secondary main" type="button" disabled>
                  <LoaderCircle class="spin" size={16} strokeWidth={1.75} aria-hidden="true" />
                  Disconnecting…
                </button>
              {:else}
                {@const choices = transportChoices(profile.transports)}
                {@const preferred = defaultTransport(profile.transports)}
                {@const blocked = locked || otherActive}
                {#if preferred && choices.length > 1}
                  {@const pid = profile.id}
                  {@const menuId = `${uid}-${pid}-transports`}
                  {@const open = menuFor === profile.id && !blocked}
                  <div class="split" role="group" onfocusout={(event) => onSplitFocusOut(event, profile.id)}>
                    <button
                      class="btn btn-primary main split-main"
                      type="button"
                      title="Connect with {transportLabel(preferred)}"
                      disabled={blocked}
                      onclick={() => onconnect(profile.id, preferred)}
                    >
                      <Plug size={16} strokeWidth={1.75} aria-hidden="true" />
                      Connect
                    </button>
                    <button
                      class="btn btn-primary split-toggle"
                      type="button"
                      aria-label="Choose transport"
                      title="Choose transport"
                      aria-haspopup="menu"
                      aria-expanded={open}
                      aria-controls={open ? menuId : undefined}
                      disabled={blocked}
                      bind:this={menuToggles[profile.id]}
                      onclick={() => (menuFor = open ? null : profile.id)}
                      onkeydown={(event) => onToggleKey(event, profile.id)}
                    >
                      <ChevronDown size={16} strokeWidth={1.75} aria-hidden="true" />
                    </button>
                    {#if open}
                      <div
                        id={menuId}
                        class="menu"
                        role="menu"
                        aria-label="Connect with"
                        tabindex="-1"
                        onkeydown={(event) => onMenuKey(event, profile.id)}
                        {@attach transportMenu(pid)}
                      >
                        {#each choices as transport (transport)}
                          <button
                            class="menu-item"
                            type="button"
                            role="menuitem"
                            tabindex="-1"
                            onclick={() => pickTransport(profile.id, transport)}>{transportLabel(transport)}</button
                          >
                        {/each}
                      </div>
                    {/if}
                  </div>
                {:else}
                  <button
                    class="btn btn-primary main"
                    type="button"
                    disabled={blocked}
                    onclick={() => onconnect(profile.id, preferred)}
                  >
                    <Plug size={16} strokeWidth={1.75} aria-hidden="true" />
                    Connect
                  </button>
                {/if}
              {/if}
              <span class="tools">
                <button
                  class="btn btn-icon"
                  type="button"
                  aria-label="Rename"
                  title="Rename"
                  disabled={locked}
                  bind:this={renameButtons[profile.id]}
                  onclick={() => startRename(profile)}
                >
                  <Pencil size={16} strokeWidth={1.75} aria-hidden="true" />
                </button>
                <button
                  class="btn btn-icon btn-danger"
                  type="button"
                  aria-label="Remove"
                  title={phase === "idle" ? "Remove" : "Disconnect before removing"}
                  disabled={locked || phase !== "idle"}
                  onclick={() => (confirming = profile.id)}
                >
                  <Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />
                </button>
              </span>
            {/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .profiles {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 16px 6px;
  }

  h2 {
    font-size: 15px;
    font-weight: 600;
  }

  .empty {
    display: grid;
    justify-items: start;
    gap: 6px;
    padding: 12px 16px;
  }

  .empty h3 {
    font-size: 13px;
    font-weight: 600;
  }

  .note {
    padding: 4px 16px;
    color: var(--muted);
  }

  .empty p {
    margin-bottom: 8px;
    color: var(--muted);
  }

  .list {
    flex: 1;
    min-height: 0;
    margin: 0;
    padding: 0 0 12px;
    overflow-y: auto;
    list-style: none;
  }

  .row {
    display: grid;
    gap: 8px;
    padding: 12px 16px;
  }

  .divided {
    border-top: 1px solid var(--line);
  }

  .row:hover {
    background: var(--hover);
  }

  .row.connected {
    box-shadow: inset 2px 0 0 var(--connected);
  }

  .info {
    min-width: 0;
  }

  .name {
    font-size: 15px;
    font-weight: 550;
    overflow-wrap: anywhere;
  }

  .meta {
    color: var(--muted);
    overflow-wrap: anywhere;
  }

  .transports {
    display: flex;
    gap: 8px;
    color: var(--muted);
    font-size: 12px;
  }

  .tunnel {
    margin-left: auto;
    color: var(--connected);
    font-size: 12px;
    font-weight: 550;
  }

  .tunnel-label {
    font-weight: 400;
  }

  .name-field {
    min-height: 30px;
    padding: 3px 8px;
    margin-left: -9px;
    width: calc(100% + 9px);
    font-size: 15px;
    font-weight: 550;
  }

  .hint {
    margin: 4px 0 2px;
    color: var(--muted);
    font-size: 12px;
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }

  .main {
    min-width: 136px;
    justify-content: center;
  }

  .split {
    display: inline-flex;
  }

  .split-main {
    min-width: 108px;
    border-start-end-radius: 0;
    border-end-end-radius: 0;
  }

  .split-toggle {
    justify-content: center;
    width: 28px;
    padding: 0;
    border-inline-start-color: color-mix(in srgb, var(--paper) 28%, transparent);
    border-start-start-radius: 0;
    border-end-start-radius: 0;
  }

  .menu {
    position: fixed;
    z-index: 20;
    display: grid;
    align-content: start;
    overflow-y: auto;
    padding: 4px;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--surface);
    box-shadow: 0 6px 20px rgb(0 0 0 / 0.14);
  }

  .menu-item {
    min-height: 28px;
    padding: 4px 10px;
    border: 0;
    border-radius: 4px;
    background: transparent;
    font-weight: 550;
    text-align: start;
    white-space: nowrap;
    cursor: pointer;
  }

  .menu-item:hover,
  .menu-item:focus-visible {
    background: var(--hover);
  }

  .menu-item:focus-visible {
    outline-offset: -2px;
  }

  .tools {
    display: flex;
    gap: 2px;
    margin-left: auto;
  }

  .confirm-text {
    margin-right: 4px;
  }
</style>
