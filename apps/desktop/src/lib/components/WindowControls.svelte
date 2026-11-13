<script lang="ts">
  import Minus from "@lucide/svelte/icons/minus";
  import X from "@lucide/svelte/icons/x";
  import { closeWindow, dragWindow, minimizeWindow } from "$lib/window";

  interface Props {
    modal: boolean;
  }

  let { modal }: Props = $props();
</script>

{#if modal}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="drag-strip" data-tauri-drag-region onmousedown={dragWindow}></div>
{/if}

<div class="controls" role="group" aria-label="Window controls">
  <button class="caption" type="button" aria-label="Minimize" title="Minimize" onclick={minimizeWindow}>
    <Minus size={16} strokeWidth={1.5} aria-hidden="true" />
  </button>
  <button class="caption close" type="button" aria-label="Close" title="Close" onclick={closeWindow}>
    <X size={16} strokeWidth={1.5} aria-hidden="true" />
  </button>
</div>

<style>
  .drag-strip {
    position: fixed;
    top: 0;
    left: 0;
    right: var(--caption-width);
    z-index: 30;
    height: var(--toolbar);
  }

  .controls {
    position: fixed;
    top: 0;
    right: 0;
    z-index: 31;
    display: flex;
    width: var(--caption-width);
    height: var(--toolbar);
  }

  .caption {
    display: inline-flex;
    flex: 1;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 0;
    border: 0;
    border-radius: 0;
    background: transparent;
    color: var(--ink);
    cursor: default;
  }

  .caption:hover {
    background: var(--hover);
  }

  .close:hover {
    background: #c42b1c;
    color: #fff;
  }

  .caption:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: -2px;
  }
</style>
