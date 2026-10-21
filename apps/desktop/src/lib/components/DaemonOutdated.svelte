<script lang="ts">
  import type { VersionMismatch } from "$lib/types";

  interface Props {
    mismatch: VersionMismatch;
  }

  let { mismatch }: Props = $props();

  const daemonVersion = $derived(mismatch.daemon_version ?? "a different version");
</script>

<section class="notice" role="status" aria-labelledby="outdated-title">
  <h2 id="outdated-title">The WyVPN service restarts after you disconnect</h2>
  <p>The background service runs a different version. It updates on its own once no tunnel is connected.</p>
  <dl>
    <div>
      <dt>App</dt>
      <dd class="selectable">{mismatch.client_version}</dd>
    </div>
    <div>
      <dt>Service</dt>
      <dd class="selectable">{daemonVersion}</dd>
    </div>
  </dl>
  <p>If this stays after you disconnect, restart your Mac.</p>
</section>

<style>
  .notice {
    display: grid;
    gap: 8px;
    padding: 12px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--line);
    box-shadow: inset 2px 0 0 var(--connecting);
  }

  h2 {
    font-size: 13px;
    font-weight: 600;
  }

  p,
  dt {
    color: var(--muted);
  }

  dl {
    display: grid;
    gap: 2px;
    font-size: 12px;
  }

  dl div {
    display: flex;
    gap: 6px;
  }

  dd {
    color: var(--ink);
  }
</style>
