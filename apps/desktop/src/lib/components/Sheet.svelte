<script module lang="ts">
  const openSheets: symbol[] = [];
</script>

<script lang="ts">
  import type { Snippet } from "svelte";
  import type { Attachment } from "svelte/attachments";
  import X from "@lucide/svelte/icons/x";
  import { cubicIn, cubicOut } from "svelte/easing";
  import type { TransitionConfig } from "svelte/transition";
  import { dragWindow } from "$lib/window";

  const reduced = () =>
    typeof matchMedia !== "function" || matchMedia("(prefers-reduced-motion: reduce)").matches;

  function slide(_node: Element, { leaving = false } = {}): TransitionConfig {
    return {
      duration: reduced() ? 0 : leaving ? 140 : 180,
      easing: leaving ? cubicIn : cubicOut,
      css: (t) => `transform: translateY(${(1 - t) * 100}%)`,
    };
  }

  function dim(_node: Element, { leaving = false } = {}): TransitionConfig {
    return {
      duration: reduced() ? 0 : leaving ? 140 : 180,
      css: (t) => `opacity: ${t}`,
    };
  }

  interface Props {
    title: string;
    size?: "fit" | "full";
    closeOnBackdrop?: boolean;
    onclose: () => void;
    children: Snippet;
  }

  let { title, size = "fit", closeOnBackdrop = true, onclose, children }: Props = $props();

  const id = $props.id();
  const token = Symbol();

  const trapFocus: Attachment<HTMLElement> = (node) => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    openSheets.push(token);
    if (!node.contains(document.activeElement)) node.focus();
    return () => {
      openSheets.splice(openSheets.indexOf(token), 1);
      if (previous?.isConnected) previous.focus();
    };
  };

  function onkeydown(event: KeyboardEvent) {
    if (event.key !== "Escape" || openSheets.at(-1) !== token) return;
    event.preventDefault();
    onclose();
  }
</script>

<svelte:window {onkeydown} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div
  class="scrim"
  aria-hidden="true"
  data-tauri-drag-region={closeOnBackdrop ? undefined : ""}
  onmousedown={closeOnBackdrop ? undefined : dragWindow}
  onclick={closeOnBackdrop ? onclose : undefined}
  in:dim|global
  out:dim|global={{ leaving: true }}
></div>
<div
  class="sheet"
  class:full={size === "full"}
  in:slide|global
  out:slide|global={{ leaving: true }}
  role="dialog"
  aria-modal="true"
  aria-labelledby="{id}-title"
  tabindex="-1"
  {@attach trapFocus}
>
  <header class="head">
    <h2 id="{id}-title">{title}</h2>
    <button class="btn btn-icon" type="button" aria-label="Close" title="Close" onclick={onclose}>
      <X size={16} strokeWidth={1.75} aria-hidden="true" />
    </button>
  </header>
  <div class="body">
    {@render children()}
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    background: var(--scrim);
  }

  .sheet {
    position: fixed;
    inset: auto 0 0 0;
    max-height: calc(100vh - var(--sheet-top));
    overflow-y: auto;
    will-change: transform;
    border-radius: 12px 12px 0 0;
    background: var(--surface);
  }

  .sheet.full {
    top: var(--sheet-top);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .body {
    padding: 0 16px 16px;
  }

  .full .body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  .sheet:focus {
    outline: none;
  }

  .head {
    position: sticky;
    top: 0;
    z-index: 1;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 8px;
    padding: 14px 8px 6px 16px;
    background: var(--surface);
  }

  h2 {
    font-size: 15px;
    font-weight: 600;
  }



</style>
