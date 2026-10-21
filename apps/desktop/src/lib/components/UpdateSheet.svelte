<script lang="ts">
  import LoaderCircle from "@lucide/svelte/icons/loader-circle";
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import { tick } from "svelte";
  import type { Attachment } from "svelte/attachments";
  import { formatProgress, formatReleaseDate, offerOf, progressPercent, updates } from "$lib/update.svelte";
  import Sheet from "./Sheet.svelte";

  interface Props {
    vpnActive: boolean;
  }

  let { vpnActive }: Props = $props();

  const id = $props.id();
  const windows = typeof navigator !== "undefined" && /Windows/.test(navigator.userAgent);

  const current = $derived(updates.state);
  const offer = $derived(offerOf(current));
  const installing = $derived(updates.installing);
  const released = $derived(offer ? formatReleaseDate(offer.date) : null);
  const version = $derived("version" in current ? current.version : "");
  // Waits for Sheet's own initial focus so its focus return on close stays intact.
  const claimFocus: Attachment<HTMLElement> = (node) => {
    void tick().then(() => {
      const dialog = node.closest("[role='dialog']");
      const active = document.activeElement;
      if (node.isConnected && dialog && (active === dialog || !dialog.contains(active))) node.focus();
    });
  };

  const percent = $derived(
    current.state === "downloading" ? progressPercent(current.received, current.total) : null,
  );
</script>

<Sheet title="Software update" closable={!installing} onclose={() => updates.close()}>
  {#if offer}
    <p class="headline selectable">
      {offer.installable ? `WyVPN ${offer.version} is available` : `Version ${offer.version} available`}
    </p>
    {#if released}
      <p class="help">Released {released}</p>
    {/if}

    {#if offer.notes}
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <div class="notes selectable" role="region" aria-label="Release notes" tabindex="0">{offer.notes}</div>
    {/if}

    {#if offer.installable}
      {#if vpnActive}
        <p class="warn" role="note">
          <TriangleAlert class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
          <span>Installing disconnects the VPN. Connect again after WyVPN restarts.</span>
        </p>
      {/if}
      <p class="help">
        {windows
          ? "Windows asks for permission to install. WyVPN restarts when it's done."
          : "WyVPN restarts when the update is installed."}
      </p>
      <div class="actions">
        <button class="btn btn-primary" type="button" onclick={() => updates.install()}>Install</button>
        <button class="btn btn-text" type="button" onclick={() => updates.later()}>Later</button>
      </div>
    {:else}
      <p class="help">Install it with your package manager or from the release page.</p>
      <div class="actions">
        <button class="btn btn-primary" type="button" onclick={() => updates.openPage()}>Open release page</button>
        <button class="btn btn-text" type="button" onclick={() => updates.later()}>Later</button>
      </div>
    {/if}
  {:else if installing}
    <div class="progress-view" role="status" tabindex="-1" {@attach claimFocus}>
      <p class="headline">
        {current.state === "relaunching" ? "Restarting WyVPN" : `Installing WyVPN ${version}`}
      </p>
      <div class="progress">
        {#if current.state === "downloading" && percent !== null}
          <progress aria-labelledby="{id}-step" max="100" value={percent}></progress>
        {:else}
          <progress aria-labelledby="{id}-step"></progress>
        {/if}
        <p class="help" id="{id}-step">
          {#if current.state === "disconnecting"}
            Disconnecting the VPN…
          {:else if current.state === "downloading"}
            Downloading… {formatProgress(current.received, current.total)}
          {:else if current.state === "installing"}
            Installing…
          {:else}
            Restarting…
          {/if}
        </p>
      </div>
    </div>
    <div class="actions">
      <button class="btn btn-primary" type="button" disabled>Install</button>
      <button class="btn btn-text" type="button" disabled>Later</button>
    </div>
  {:else if current.state === "checking"}
    <p class="checking" role="status">
      <LoaderCircle class="spin" size={16} strokeWidth={2} aria-hidden="true" />
      Checking for updates…
    </p>
  {:else if current.state === "up_to_date"}
    <p class="headline" role="status">WyVPN is up to date</p>
    <p class="help">You have the latest version.</p>
    <div class="actions">
      <button class="btn btn-primary" type="button" onclick={() => updates.close()}>OK</button>
    </div>
  {:else}
    {#if current.state === "failed"}
      <p class="alert" role="alert">{current.message || "The update check failed."}</p>
    {/if}
    <div class="actions">
      <button class="btn btn-primary" type="button" onclick={() => updates.check()}>
        {current.state === "failed" ? "Check again" : "Check for updates"}
      </button>
    </div>
  {/if}

  {#if updates.error}
    <p class="alert error" role="alert">{updates.error}</p>
  {/if}
</Sheet>

<style>
  .headline {
    font-size: 15px;
    font-weight: 550;
    overflow-wrap: anywhere;
  }

  .help {
    margin-top: 4px;
    color: var(--muted);
    font-size: 12px;
  }

  .notes {
    max-height: 40vh;
    margin-top: 12px;
    padding: 8px 10px;
    overflow-y: auto;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--paper);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .warn {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    margin-top: 12px;
    color: var(--connecting);
  }

  .warn :global(.glyph) {
    flex: none;
    margin-top: 3px;
  }

  .progress-view:focus {
    outline: none;
  }

  .progress {
    margin-top: 12px;
  }

  progress {
    display: block;
    width: 100%;
    height: 6px;
    accent-color: var(--ink);
  }

  .checking {
    display: flex;
    gap: 8px;
    align-items: center;
    color: var(--muted);
  }

  .actions {
    display: flex;
    gap: 8px;
    margin-top: 16px;
  }

  .error {
    margin-top: 10px;
  }
</style>
