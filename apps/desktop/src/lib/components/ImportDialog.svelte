<script lang="ts">
  import { daemon } from "$lib/daemon.svelte";
  import { describeError, duplicateName, isDuplicateImport, toCommandError } from "$lib/errors";
  import { joinNames } from "$lib/format";
  import type { ErrorBody, ProfileSummary } from "$lib/types";
  import Sheet from "./Sheet.svelte";

  interface Props {
    onclose: () => void;
  }

  let { onclose }: Props = $props();

  type Source = "file" | "link";
  type Replace = { via: "retry"; retry: string } | { via: "link"; link: string } | { via: "file" };
  type Phase =
    | { kind: "idle"; error: string | null }
    | { kind: "pending"; source: Source }
    | { kind: "conflict"; source: Source; name: string | null; replace: Replace }
    | { kind: "done"; names: string[] };

  const linkId = $props.id();
  let link = $state("");
  let phase = $state<Phase>({ kind: "idle", error: null });

  const pending = $derived(phase.kind === "pending");
  const disabled = $derived(pending || !daemon.available);

  function importWith(source: Source, replace: Replace | null): Promise<ProfileSummary[] | null> {
    if (replace?.via === "retry") return daemon.replaceImport(replace.retry);
    if (replace?.via === "link") return daemon.importLink(replace.link, true);
    if (replace?.via === "file") return daemon.importFile(true);
    return source === "file" ? daemon.importFile(false) : daemon.importLink(link.trim(), false);
  }

  function replaceFor(source: Source, error: ErrorBody): Replace {
    if (error.retry) return { via: "retry", retry: error.retry };
    return source === "link" ? { via: "link", link: link.trim() } : { via: "file" };
  }

  async function run(source: Source, replace: Replace | null) {
    phase = { kind: "pending", source };
    try {
      const imported = await importWith(source, replace);
      if (imported === null) {
        phase = { kind: "idle", error: null };
        return;
      }
      if (source === "link") link = "";
      phase = { kind: "done", names: imported.map((profile) => profile.name) };
    } catch (raw) {
      const error = toCommandError(raw).toBody();
      phase = isDuplicateImport(error)
        ? { kind: "conflict", source, name: duplicateName(error), replace: replaceFor(source, error) }
        : { kind: "idle", error: describeError(error) };
    }
  }

  function submitLink(event: SubmitEvent) {
    event.preventDefault();
    if (link.trim()) void run("link", null);
  }

  function close() {
    link = "";
    onclose();
  }
</script>

<Sheet title="Import profile" onclose={close}>
  {#if phase.kind === "done"}
    <p class="result" role="status">Imported {joinNames(phase.names)}</p>
  {:else if phase.kind === "conflict"}
    {@const { source, replace } = phase}
    <p class="lead">
      {#if phase.name}<strong>{phase.name}</strong>{:else}This profile{/if} is already imported. Replace
      it with the new copy?
    </p>
    <div class="actions">
      <button class="btn btn-primary" type="button" disabled={!daemon.available} onclick={() => run(source, replace)}
        >Replace</button
      >
      <button class="btn btn-text" type="button" onclick={() => (phase = { kind: "idle", error: null })}
        >Cancel</button
      >
    </div>
  {:else}
    <div class="choose">
      <button class="btn btn-primary" type="button" {disabled} onclick={() => run("file", null)}>
        {phase.kind === "pending" && phase.source === "file" ? "Importing…" : "Choose file…"}
      </button>
    </div>

    <form class="link" onsubmit={submitLink}>
      <label class="label" for={linkId}>Or paste a profile link</label>
      <div class="link-row">
        <input
          id={linkId}
          class="field"
          type="text"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
          bind:value={link}
          disabled={pending}
        />
        <button class="btn btn-secondary" type="submit" disabled={disabled || !link.trim()}>
          {phase.kind === "pending" && phase.source === "link" ? "Importing…" : "Import"}
        </button>
      </div>
    </form>

    {#if phase.kind === "idle" && phase.error}
      <p class="alert" role="alert">{phase.error}</p>
    {/if}

  {/if}
</Sheet>

<style>
  .lead,
  .result {
    overflow-wrap: anywhere;
  }

  .result {
    font-size: 15px;
    font-weight: 550;
  }

  .link {
    margin-top: 16px;
  }

  .link-row {
    display: flex;
    gap: 8px;
  }

  .link-row .field {
    flex: 1;
    min-width: 0;
  }

  .alert {
    margin-top: 10px;
  }

  .actions {
    display: flex;
    gap: 8px;
    margin-top: 16px;
  }
</style>
