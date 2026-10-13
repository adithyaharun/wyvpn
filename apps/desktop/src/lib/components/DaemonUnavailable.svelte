<script lang="ts">
  import ServerOff from "@lucide/svelte/icons/server-off";

  interface Props {
    socket: string;
  }

  let { socket }: Props = $props();
</script>

<section class="unavailable" aria-labelledby="unavailable-title">
  <h1 id="unavailable-title">
    <ServerOff class="glyph" size={16} strokeWidth={2} aria-hidden="true" />
    WyVPN service isn't running
  </h1>
  <p>Start <span class="cmd">wyvpnd</span> on this computer. This window reconnects on its own once the service is up.</p>
  {#if socket}
    <p class="socket">
      <span class="socket-label">Looking for</span>
      <span class="socket-path">{socket}</span>
    </p>
  {/if}
</section>

<style>
  .unavailable {
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
    color: var(--error);
  }

  p {
    color: var(--muted);
  }

  .cmd {
    color: var(--ink);
    font-weight: 550;
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
</style>
