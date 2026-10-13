<script lang="ts">
  import { onMount } from "svelte";
  import { daemon } from "$lib/daemon.svelte";
  import { describeLogError } from "$lib/errors";
  import { formatClock } from "$lib/format";
  import CopyButton from "./CopyButton.svelte";
  import Sheet from "./Sheet.svelte";

  interface Props {
    onclose: () => void;
  }

  let { onclose }: Props = $props();

  let scroller = $state<HTMLElement>();
  let following = $state(true);
  let loading = $state(true);

  const log = $derived(daemon.log);
  const lines = $derived(log.lines);
  const profileName = $derived(
    log.profileId ? (daemon.profiles.find((p) => p.id === log.profileId)?.name ?? "") : "",
  );
  const error = $derived(daemon.logError ? describeLogError(daemon.logError) : null);

  onMount(() => {
    void daemon.refreshLog().finally(() => (loading = false));
  });

  $effect(() => {
    void lines;
    if (following && scroller) scroller.scrollTop = scroller.scrollHeight;
  });

  function onscroll() {
    if (!scroller) return;
    following = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 8;
  }

  function jumpToLatest() {
    following = true;
    if (scroller) scroller.scrollTop = scroller.scrollHeight;
  }

  function allText(): string {
    return lines.map((line) => `${formatClock(line.at_ms)} ${line.text}`).join("\n");
  }
</script>

<Sheet title="Connection log" size="full" {onclose}>
  <div class="panel">
    {#if error}
      <p class="alert" role="alert">{error}</p>
    {:else}
      {#if profileName}
        <p class="lead">Log for <span class="profile">{profileName}</span></p>
      {/if}
      <div class="frame">
        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <div
          class="scroller"
          role="region"
          aria-label="Log lines"
          tabindex="0"
          bind:this={scroller}
          {onscroll}
        >
          {#if lines.length === 0}
            <p class="empty">{loading ? "Loading the log…" : "No log yet. Lines appear here once you connect."}</p>
          {:else}
            <ol class="lines">
              {#each lines as line (line.seq)}
                <li class="line" class:daemon={line.source === "daemon"}>
                  <time class="at" datetime={new Date(line.at_ms).toISOString()}>{formatClock(line.at_ms)}</time>
                  <span class="text">{line.text}</span>
                </li>
              {/each}
            </ol>
          {/if}
        </div>
        {#if !following}
          <button class="btn btn-secondary latest" type="button" onclick={jumpToLatest}>Show latest</button>
        {/if}
      </div>
    {/if}

    <div class="actions">
      <CopyButton value={allText} label="Copy log" text="Copy log" disabled={lines.length === 0} />
    </div>
  </div>
</Sheet>

<style>
  .lead {
    margin: -6px 0 10px;
    color: var(--muted);
    overflow-wrap: anywhere;
  }

  .profile {
    color: var(--ink);
    font-weight: 550;
  }

  .panel {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .frame {
    position: relative;
    display: flex;
    flex: 1;
    min-height: 160px;
  }

  .scroller {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: 8px 0;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--paper);
    user-select: text;
  }

  .scroller:focus-visible {
    outline-offset: 0;
  }

  .lines {
    margin: 0;
    padding: 0;
    list-style: none;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 11.5px;
    line-height: 1.5;
  }

  .line {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 10px;
    padding: 0 10px;
  }

  .at {
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }

  .text {
    min-width: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .daemon .text {
    font-weight: 600;
  }

  .empty {
    padding: 4px 10px;
    color: var(--muted);
  }

  .latest {
    position: absolute;
    right: 10px;
    bottom: 10px;
    box-shadow: 0 2px 8px rgb(0 0 0 / 0.12);
  }

  .actions {
    display: flex;
    gap: 8px;
    margin-top: 12px;
  }
</style>
