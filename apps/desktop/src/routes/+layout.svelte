<script lang="ts">
  import "../app.css";
  import Toaster from "$lib/components/Toaster.svelte";
  import { toasts } from "$lib/toast.svelte";
  import { dragWindow } from "$lib/window";

  let { children } = $props();
</script>

<svelte:boundary onerror={(error) => toasts.report(error)}>
  {@render children()}

  {#snippet failed(_error, reset)}
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="failed" data-tauri-drag-region onmousedown={dragWindow}>
      <p>This view couldn't be shown.</p>
      <button class="btn btn-secondary" type="button" onclick={reset}>Try again</button>
    </div>
  {/snippet}
</svelte:boundary>

<Toaster />

<style>
  .failed {
    display: grid;
    place-content: center;
    justify-items: center;
    gap: 10px;
    height: 100vh;
    padding: 16px;
    color: var(--muted);
  }
</style>
