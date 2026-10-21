<script lang="ts">
  import CircleAlert from "@lucide/svelte/icons/circle-alert";
  import X from "@lucide/svelte/icons/x";
  import { onMount } from "svelte";
  import { cubicIn, cubicOut } from "svelte/easing";
  import type { TransitionConfig } from "svelte/transition";
  import { api } from "$lib/api";
  import { captureErrors, formatDetails, toasts, type Toast } from "$lib/toast.svelte";
  import type { AppInfo } from "$lib/types";
  import CopyButton from "./CopyButton.svelte";

  const reduced = () =>
    typeof matchMedia !== "function" || matchMedia("(prefers-reduced-motion: reduce)").matches;

  function rise(_node: Element, { leaving = false } = {}): TransitionConfig {
    return {
      duration: reduced() ? 0 : leaving ? 140 : 200,
      easing: leaving ? cubicIn : cubicOut,
      css: (t) => `opacity: ${t}; transform: translateY(${(1 - t) * 12}px)`,
    };
  }

  let info: Promise<AppInfo | null> | undefined;

  function appInfo(): Promise<AppInfo | null> {
    info ??= api.appInfo().catch(() => null);
    return info;
  }

  async function details(toast: Toast): Promise<string> {
    return formatDetails(toast, await appInfo());
  }

  function onfocusout(event: FocusEvent, id: number) {
    const next = event.relatedTarget;
    if (next instanceof Node && (event.currentTarget as HTMLElement).contains(next)) return;
    toasts.resume(id, "focus");
  }

  onMount(() => captureErrors(window));
</script>

<div class="toaster">
  {#each toasts.items as toast (toast.id)}
    <div
      class="toast"
      role="alert"
      aria-atomic="true"
      in:rise
      out:rise={{ leaving: true }}
      onmouseenter={() => toasts.pause(toast.id, "hover")}
      onmouseleave={() => toasts.resume(toast.id, "hover")}
      onfocusin={() => toasts.pause(toast.id, "focus")}
      onfocusout={(event) => onfocusout(event, toast.id)}
    >
      <CircleAlert class="glyph" size={16} strokeWidth={1.75} aria-hidden="true" />
      <div class="text">
        <p class="title">Something went wrong in WyVPN.</p>
        {#if toast.message}
          <p class="message selectable" title={toast.message}>{toast.message}</p>
        {/if}
        <div class="actions">
          <CopyButton value={() => details(toast)} label="Copy details" text="Copy details" />
        </div>
      </div>
      <button
        class="btn btn-icon"
        type="button"
        aria-label="Dismiss"
        title="Dismiss"
        onclick={() => toasts.dismiss(toast.id)}
      >
        <X size={16} strokeWidth={1.75} aria-hidden="true" />
      </button>
    </div>
  {/each}
</div>

<style>
  .toaster {
    position: fixed;
    inset: auto 12px 12px;
    z-index: 10;
    display: grid;
    justify-items: center;
    gap: 8px;
    pointer-events: none;
  }

  .toast {
    display: grid;
    grid-template-columns: 16px 1fr auto;
    align-items: start;
    gap: 8px;
    width: min(100%, 420px);
    padding: 10px 6px 10px 12px;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--surface);
    box-shadow:
      inset 2px 0 0 var(--error),
      0 6px 20px rgb(0 0 0 / 0.14);
    pointer-events: auto;
    will-change: transform;
  }

  .toast > :global(.glyph) {
    margin-top: 1px;
    color: var(--error);
  }

  .text {
    display: grid;
    gap: 2px;
    min-width: 0;
    padding-top: 1px;
  }

  .title {
    font-weight: 550;
  }

  .message {
    display: -webkit-box;
    overflow: hidden;
    color: var(--muted);
    font-size: 12px;
    overflow-wrap: anywhere;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 2;
    line-clamp: 2;
  }

  .actions {
    display: flex;
    margin-top: 6px;
  }

  .btn-icon {
    margin-top: -5px;
  }
</style>
