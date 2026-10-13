<script lang="ts">
  import ShieldCheck from "@lucide/svelte/icons/shield-check";
  import { onMount } from "svelte";
  import { api } from "$lib/api";
  import { daemon } from "$lib/daemon.svelte";
  import { describeError, toCommandError } from "$lib/errors";
  import type { ServiceStatus } from "$lib/types";

  interface Props {
    setup: ServiceStatus | null;
  }

  let { setup }: Props = $props();

  const POLL_MS = 2000;
  let current = $state<ServiceStatus | null>(null);
  let error = $state<string | null>(null);
  let working = false;

  const status = $derived(current ?? setup);

  async function register() {
    try {
      current = await api.registerService();
      error = null;
    } catch (raw) {
      error = describeError(toCommandError(raw).toBody());
    }
  }

  async function tick() {
    if (working) return;
    working = true;
    try {
      const next = await api.serviceStatus();
      if (next === null) return;
      current = next;
      if ((next === "not_registered" || next === "not_found") && error === null) await register();
      if (current === "enabled") await daemon.refreshAvailability();
    } catch (raw) {
      error = describeError(toCommandError(raw).toBody());
    } finally {
      working = false;
    }
  }

  async function retry() {
    error = null;
    await tick();
  }

  onMount(() => {
    void tick();
    const timer = setInterval(() => void tick(), POLL_MS);
    return () => clearInterval(timer);
  });
</script>

<section class="setup" aria-labelledby="setup-title">
  <h1 id="setup-title">
    <ShieldCheck class="glyph" size={16} strokeWidth={2} aria-hidden="true" />
    Approve the WyVPN background service
  </h1>
  <p>WyVPN needs its background service approved before it can connect. You only do this once.</p>

  {#if error}
    <p class="alert" role="alert">{error}</p>
    <div class="actions">
      <button class="btn btn-secondary" type="button" onclick={retry}>Try again</button>
    </div>
  {:else if status === "requires_approval"}
    <p>Turn on WyVPN under Allow in the Background in System Settings. This screen continues on its own.</p>
    <div class="actions">
      <button class="btn btn-primary" type="button" onclick={() => api.openLoginItems()}>
        Open System Settings
      </button>
    </div>
  {:else if status === "enabled"}
    <p role="status">Approved. Starting the service…</p>
  {:else}
    <p role="status">Setting up the service…</p>
  {/if}
</section>

<style>
  .setup {
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

  .alert {
    color: var(--error);
  }

  .actions {
    display: flex;
    gap: 8px;
  }
</style>
