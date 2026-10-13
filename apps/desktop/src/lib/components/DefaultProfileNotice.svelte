<script lang="ts">
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";
  import { api } from "$lib/api";
  import type { StartupNotice } from "$lib/types";

  interface Props {
    onopensettings: () => void;
  }

  let { onopensettings }: Props = $props();

  let notice = $state<StartupNotice | null>(null);

  onMount(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;

    // Listen before taking the stored notice so one emitted in between isn't lost.
    listen<StartupNotice>("app://default-profile-missing", ({ payload }) => (notice = payload))
      .then(
        (stop) => {
          if (disposed) stop();
          else unlisten = stop;
        },
        () => {},
      )
      .then(() => api.takeStartupNotice())
      .then((stored) => {
        if (stored && !disposed) notice = stored;
      })
      .catch(() => {});

    return () => {
      disposed = true;
      unlisten?.();
    };
  });

  function openSettings() {
    notice = null;
    onopensettings();
  }
</script>

{#if notice}
  <div class="notice" role="status">
    <p>Your default profile was removed, so WyVPN didn't connect automatically. Choose another in Settings.</p>
    <div class="actions">
      <button class="btn btn-secondary" type="button" onclick={openSettings}>Open Settings</button>
      <button class="btn btn-text" type="button" onclick={() => (notice = null)}>Dismiss</button>
    </div>
  </div>
{/if}

<style>
  .notice {
    display: grid;
    gap: 8px;
    padding: 12px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--line);
    box-shadow: inset 2px 0 0 var(--connecting);
  }

  .actions {
    display: flex;
    gap: 6px;
  }

  .actions .btn-text {
    color: var(--muted);
  }
</style>
