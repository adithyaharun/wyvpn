<script lang="ts">
  import FilePlus from "@lucide/svelte/icons/file-plus";
  import ScrollText from "@lucide/svelte/icons/scroll-text";
  import Settings from "@lucide/svelte/icons/settings";
  import { dragWindow } from "$lib/window";

  interface Props {
    available: boolean;
    onimport: () => void;
    onlog: () => void;
    onsettings: () => void;
  }

  let { available, onimport, onlog, onsettings }: Props = $props();
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<header class="toolbar" data-tauri-drag-region onmousedown={dragWindow}>
  <span class="name" data-tauri-drag-region>WyVPN</span>
  <div class="spacer" data-tauri-drag-region></div>
  <div class="actions" data-tauri-drag-region>
    <button
      class="btn btn-icon"
      type="button"
      aria-label="Import profile"
      title="Import profile"
      disabled={!available}
      onclick={onimport}
    >
      <FilePlus size={16} strokeWidth={1.75} aria-hidden="true" />
    </button>
    <button
      class="btn btn-icon"
      type="button"
      aria-label="Connection log"
      title="Connection log"
      disabled={!available}
      onclick={onlog}
    >
      <ScrollText size={16} strokeWidth={1.75} aria-hidden="true" />
    </button>
    <button class="btn btn-icon" type="button" aria-label="Settings" title="Settings" onclick={onsettings}>
      <Settings size={16} strokeWidth={1.75} aria-hidden="true" />
    </button>
  </div>
</header>

<style>
  .toolbar {
    display: flex;
    flex: none;
    align-items: center;
    gap: 8px;
    height: var(--toolbar);
    padding: var(--toolbar-pad-top, 0) 8px var(--toolbar-pad-bottom, 0) var(--toolbar-inset);
    background: var(--surface);
    cursor: default;
  }

  .name {
    color: var(--muted);
    font-size: 13px;
    font-weight: 550;
  }

  .spacer {
    flex: 1;
    align-self: stretch;
  }

  .actions {
    display: flex;
    gap: 2px;
  }
</style>
