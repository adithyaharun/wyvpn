<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "$lib/api";
  import type { OpenVpnNotice } from "$lib/types";
  import Sheet from "./Sheet.svelte";

  interface Props {
    onclose: () => void;
  }

  let { onclose }: Props = $props();

  let text = $state<string | null>(null);
  let notice = $state<OpenVpnNotice | null>(null);
  let failed = $state(false);

  onMount(() => {
    api.thirdPartyLicenses().then(
      (value) => (text = value),
      () => (failed = true),
    );
    api.openvpnNotice().then(
      (value) => (notice = value),
      () => (notice = null),
    );
  });
</script>

<Sheet title="Third-party licenses" size="full" {onclose}>
  <div class="panel">
    {#if notice}
      <p class="openvpn selectable">
        {#if notice.source_url}
          OpenVPN is licensed under {notice.license}. Source:
          <button class="link" type="button" onclick={() => api.openSupport("openvpn_source")}>
            {notice.source_url}
          </button>
        {:else}
          OpenVPN is licensed under {notice.license}. WyVPN uses your distribution's OpenVPN package.
        {/if}
      </p>
    {/if}
    {#if failed}
      <p class="alert" role="alert">The license text couldn't be loaded.</p>
    {:else}
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <div class="scroller selectable" role="region" aria-label="License text" tabindex="0">
        <pre>{text ?? "Loading…"}</pre>
      </div>
    {/if}
  </div>
</Sheet>

<style>
  .panel {
    display: flex;
    flex-direction: column;
    gap: 10px;
    height: 100%;
  }

  .openvpn {
    color: var(--muted);
    font-size: 12px;
    overflow-wrap: anywhere;
  }

  .link {
    padding: 0;
    border: 0;
    background: transparent;
    color: var(--ink);
    font: inherit;
    text-align: left;
    text-decoration: underline;
    cursor: pointer;
  }

  .scroller {
    flex: 1;
    min-height: 160px;
    overflow: auto;
    padding: 8px 10px;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--paper);
  }

  .scroller:focus-visible {
    outline-offset: 0;
  }

  pre {
    margin: 0;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 11px;
    line-height: 1.5;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
</style>
