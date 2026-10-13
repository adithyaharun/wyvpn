<script lang="ts">
  import type { Attachment } from "svelte/attachments";
  import { daemon } from "$lib/daemon.svelte";
  import type { AuthMode } from "$lib/types";
  import Sheet from "./Sheet.svelte";

  interface Props {
    profileId: string;
    profileName: string;
    mode: AuthMode;
  }

  let { profileId, profileName, mode }: Props = $props();

  const inputId = $props.id();
  let pin = $state("");

  const focus: Attachment<HTMLInputElement> = (node) => node.focus();

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!pin) return;
    const value = pin;
    pin = "";
    void daemon.submitPin(profileId, value);
  }

  function cancel() {
    pin = "";
    void daemon.cancelCredentials(profileId);
  }
</script>

<Sheet title={mode === "pin" ? "Enter your PIN" : "Sign in"} onclose={cancel}>
  {#if mode === "pin"}
    <form onsubmit={submit}>
      <p class="lead">{profileName || "This profile"} needs your PIN to connect.</p>
      <label class="label" for={inputId}>PIN</label>
      <input
        id={inputId}
        class="field"
        type="password"
        autocomplete="off"
        spellcheck="false"
        bind:value={pin}
        {@attach focus}
      />
      <button class="btn btn-primary submit" type="submit" disabled={!pin}>Connect</button>
    </form>
  {:else}
    <p class="lead">This sign-in method isn't supported yet.</p>
  {/if}
</Sheet>

<style>
  .lead {
    margin-bottom: 12px;
    overflow-wrap: anywhere;
  }

  .submit {
    width: 100%;
    justify-content: center;
    margin-top: 16px;
  }
</style>
