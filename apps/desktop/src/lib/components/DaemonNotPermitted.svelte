<script lang="ts">
  import ShieldAlert from "@lucide/svelte/icons/shield-alert";
  import CopyButton from "./CopyButton.svelte";

  const command = "sudo usermod -aG wyvpn $USER";
</script>

<section class="notice" aria-labelledby="permitted-title">
  <h1 id="permitted-title">
    <ShieldAlert class="glyph" size={16} strokeWidth={2} aria-hidden="true" />
    Join the wyvpn group
  </h1>
  <p>Your account isn't allowed to use the WyVPN service. Add yourself to the <span class="cmd">wyvpn</span> group:</p>
  <div class="command">
    <code>{command}</code>
    <CopyButton value={command} label="Copy command" />
  </div>
  <p>Then log out and back in. This window reconnects on its own afterwards.</p>
</section>

<style>
  .notice {
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

  .command {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 6px 8px;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--paper);
  }

  code {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 12px;
    user-select: text;
  }
</style>
