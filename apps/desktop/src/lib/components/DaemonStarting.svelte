<script lang="ts">
  import ClockAlert from "@lucide/svelte/icons/clock-alert";
  import LoaderCircle from "@lucide/svelte/icons/loader-circle";
  import { onMount } from "svelte";
  import { api } from "$lib/api";
  import { daemon } from "$lib/daemon.svelte";
  import { describeError, toCommandError } from "$lib/errors";

  interface Props {
    socket: string;
  }

  let { socket }: Props = $props();

  const SLOW_MS = 30_000;
  const POLL_MS = 2000;
  let slow = $state(false);
  let working = false;
  let repairing = $state(false);
  let repaired = $state(false);
  let error = $state<string | null>(null);
  let launchError = $state<string | null>(null);
  const shownError = $derived(error ?? launchError);

  async function repair() {
    if (repairing) return;
    repairing = true;
    repaired = false;
    error = null;
    try {
      await api.repairService();
      repaired = true;
      await daemon.refreshAvailability();
    } catch (raw) {
      error = describeError(toCommandError(raw).toBody());
    } finally {
      repairing = false;
    }
  }

  async function loadLaunchError() {
    try {
      launchError = await api.serviceError();
    } catch {
      // The panel still works without it.
    }
  }

  async function tick() {
    if (working) return;
    working = true;
    void loadLaunchError();
    try {
      const next = await api.serviceStatus();
      if (next !== null && next !== "enabled") await daemon.refreshAvailability();
    } catch {
      // The next tick retries.
    } finally {
      working = false;
    }
  }

  onMount(() => {
    void tick();
    const slowTimer = setTimeout(() => (slow = true), SLOW_MS);
    const pollTimer = setInterval(() => void tick(), POLL_MS);
    return () => {
      clearTimeout(slowTimer);
      clearInterval(pollTimer);
    };
  });
</script>

<section class="starting" role="status" aria-labelledby="starting-title">
  {#if slow}
    <h1 id="starting-title">
      <ClockAlert class="glyph" size={16} strokeWidth={2} aria-hidden="true" />
      The WyVPN service is taking longer than expected
    </h1>
    <p>Check that WyVPN is turned on under Allow in the Background in System Settings.</p>
    {#if socket}
      <p class="socket">
        <span class="socket-label">Looking for</span>
        <span class="socket-path">{socket}</span>
      </p>
    {/if}
    {#if shownError}
      <p class="alert" role="alert">{shownError}</p>
    {:else if repaired}
      <p role="status">Service repaired. Waiting for it to start…</p>
    {/if}
    <div class="actions">
      <button class="btn btn-primary" type="button" onclick={() => api.openLoginItems()}>
        Open System Settings
      </button>
      <button class="btn btn-secondary" type="button" disabled={repairing} onclick={repair}>
        {repairing ? "Repairing…" : "Repair background service"}
      </button>
    </div>
  {:else}
    <h1 id="starting-title">
      <LoaderCircle class="glyph spin" size={16} strokeWidth={2} aria-hidden="true" />
      Starting the WyVPN service…
    </h1>
    <p>This screen continues on its own once the service is ready.</p>
  {/if}
</section>

<style>
  .starting {
    display: grid;
    gap: 8px;
    padding: 8px 16px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--line);
  }

  h1 {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 15px;
    font-weight: 600;
  }

  h1 :global(.glyph) {
    color: var(--muted);
  }

  p {
    color: var(--muted);
  }

  .socket {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    font-size: 12px;
  }

  .socket-path {
    color: var(--ink);
    overflow-wrap: anywhere;
    user-select: text;
  }

  .alert {
    color: var(--error);
  }

  .actions {
    display: flex;
    gap: 8px;
  }
</style>
