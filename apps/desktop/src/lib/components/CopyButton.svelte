<script lang="ts">
  import Check from "@lucide/svelte/icons/check";
  import Copy from "@lucide/svelte/icons/copy";
  import X from "@lucide/svelte/icons/x";
  import { copyText } from "$lib/clipboard";

  interface Props {
    value: string | (() => string | Promise<string>);
    label: string;
    text?: string;
    disabled?: boolean;
  }

  let { value, label, text, disabled = false }: Props = $props();

  type Outcome = "copied" | "failed" | null;
  let outcome = $state<Outcome>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;

  const note = $derived(outcome === "copied" ? "Copied" : outcome === "failed" ? "Couldn't copy. Try again." : "");

  async function copy() {
    clearTimeout(timer);
    try {
      await copyText(typeof value === "function" ? await value() : value);
      outcome = "copied";
    } catch {
      outcome = "failed";
    }
    timer = setTimeout(() => (outcome = null), 1600);
  }

  $effect(() => () => clearTimeout(timer));
</script>

{#if text}
  <button class="btn btn-secondary" class:done={outcome === "copied"} type="button" {disabled} onclick={copy}>
    {#if outcome === "copied"}
      <Check size={16} strokeWidth={2} aria-hidden="true" />
      Copied
    {:else}
      <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
      {text}
    {/if}
  </button>
  <span class="sr-only" role="status">{note}</span>
{:else}
  <span class="copy">
    <button
      class="icon"
      class:done={outcome === "copied"}
      class:failed={outcome === "failed"}
      type="button"
      aria-label={label}
      title={note || label}
      {disabled}
      onclick={copy}
    >
      {#if outcome === "copied"}
        <Check size={14} strokeWidth={2} aria-hidden="true" />
      {:else if outcome === "failed"}
        <X size={14} strokeWidth={2} aria-hidden="true" />
      {:else}
        <Copy size={14} strokeWidth={1.75} aria-hidden="true" />
      {/if}
    </button>
    <span class="sr-only" role="status">{note}</span>
  </span>
{/if}

<style>
  .copy {
    display: inline-flex;
    align-items: center;
    flex: none;
  }

  .icon {
    display: inline-grid;
    place-items: center;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 0;
    border-radius: 5px;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
  }

  .icon:not(:disabled):hover {
    background: var(--hover);
    color: var(--ink);
  }

  .icon:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .done {
    color: var(--connected);
  }

  .done :global(svg) {
    animation: confirm 180ms cubic-bezier(0.2, 0.8, 0.2, 1);
  }

  .failed {
    color: var(--error);
  }

  @keyframes confirm {
    from {
      transform: scale(0.6);
      opacity: 0;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .done :global(svg) {
      animation: none;
    }
  }
</style>
