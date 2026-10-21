<script lang="ts">
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import type { VersionMismatch } from "$lib/types";

  interface Props {
    mismatch: VersionMismatch | null;
  }

  let { mismatch }: Props = $props();

  const daemonVersion = $derived(mismatch?.daemon_version ?? "an older version");
</script>

<section class="notice" aria-labelledby="incompatible-title">
  <h1 id="incompatible-title">
    <TriangleAlert class="glyph" size={16} strokeWidth={2} aria-hidden="true" />
    Update WyVPN or restart the service
  </h1>
  <p>
    This app and the background service don't speak the same version. Update WyVPN, or restart the service if you
    just updated.
  </p>
  {#if mismatch}
    <dl>
      <div>
        <dt>App</dt>
        <dd class="selectable">{mismatch.client_version} (protocol {mismatch.client_protocol})</dd>
      </div>
      <div>
        <dt>Service</dt>
        <dd class="selectable">
          {daemonVersion}{mismatch.daemon_protocol != null ? ` (protocol ${mismatch.daemon_protocol})` : ""}
        </dd>
      </div>
    </dl>
  {/if}
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
