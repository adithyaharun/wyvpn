<script lang="ts">
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
  import { isActive } from "$lib/reducer";
  import type { BusyAction, ConnectionStatus, ProfileSummary } from "$lib/types";

  interface Props {
    profiles: ProfileSummary[];
    statuses: Record<string, ConnectionStatus>;
    busy: Record<string, BusyAction>;
    available: boolean;
    onconnect: (profileId: string) => void;
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
            <p class="meta">
              {profile.user ? `${profile.user} on ${profile.server_host}` : profile.server_host}
            </p>
            {#if profile.transports.length > 0 || tunnelIp}
              <p class="transports">
                <span>{profile.transports.map(transportLabel).join(", ")}</span>
                {#if tunnelIp}
                  <span class="tunnel"><span class="tunnel-label">Tunnel IP</span> <span class="num">{tunnelIp}</span></span>
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
                <button
                  class="btn btn-primary main"
                  type="button"
                  disabled={locked || otherActive}
                  onclick={() => onconnect(profile.id)}
                >
                  <Plug size={16} strokeWidth={1.75} aria-hidden="true" />
                  Connect
                </button>
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

  .tools {
    display: flex;
    gap: 2px;
    margin-left: auto;
  }

  .confirm-text {
    margin-right: 4px;
  }
</style>
