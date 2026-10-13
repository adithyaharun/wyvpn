<script lang="ts">
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { onMount } from "svelte";
  import DaemonIncompatible from "$lib/components/DaemonIncompatible.svelte";
  import DaemonNotPermitted from "$lib/components/DaemonNotPermitted.svelte";
  import DaemonSetup from "$lib/components/DaemonSetup.svelte";
  import DaemonUnavailable from "$lib/components/DaemonUnavailable.svelte";
  import DefaultProfileNotice from "$lib/components/DefaultProfileNotice.svelte";
  import ImportDialog from "$lib/components/ImportDialog.svelte";
  import LicensesPanel from "$lib/components/LicensesPanel.svelte";
  import LogPanel from "$lib/components/LogPanel.svelte";
  import PinDialog from "$lib/components/PinDialog.svelte";
  import ProfileList from "$lib/components/ProfileList.svelte";
  import SettingsSheet from "$lib/components/SettingsSheet.svelte";
  import StatusPanel from "$lib/components/StatusPanel.svelte";
  import Toolbar from "$lib/components/Toolbar.svelte";
  import { daemon } from "$lib/daemon.svelte";
  import { describeError } from "$lib/errors";

  type Panel = "import" | "settings" | "log" | "licenses";
  let panel = $state<Panel | null>(null);

  const session = $derived(daemon.session);
  const sessionProfile = $derived(daemon.profiles.find((p) => p.id === session?.profile_id));
  const pending = $derived(daemon.pendingCredentials);
  const pendingName = $derived(
    pending ? (daemon.profiles.find((p) => p.id === pending.profileId)?.name ?? "") : "",
  );

  if (typeof navigator !== "undefined" && /Mac/.test(navigator.userAgent)) {
    document.documentElement.dataset.platform = "mac";
  }

  onMount(() => {
    const stop = daemon.start();
    let unlisten: UnlistenFn | undefined;
    let disposed = false;
    listen("app://open-licenses", () => (panel = "licenses")).then((off) => {
      if (disposed) off();
      else unlisten = off;
    });
    return () => {
      disposed = true;
      unlisten?.();
      stop();
    };
  });
</script>

<div class="app" inert={panel !== null || pending !== null}>
  <Toolbar
    available={daemon.available}
    onimport={() => (panel = "import")}
    onlog={() => (panel = "log")}
    onsettings={() => (panel = "settings")}
  />

  {#if daemon.available}
    <StatusPanel {session} profile={sessionProfile} />
  {:else if daemon.status === "incompatible"}
    <DaemonIncompatible mismatch={daemon.mismatch} />
  {:else if daemon.status === "not_permitted"}
    <DaemonNotPermitted />
  {:else if daemon.status === "needs_setup"}
    <DaemonSetup setup={daemon.setup} />
  {:else}
    <DaemonUnavailable socket={daemon.socket} />
  {/if}

  <DefaultProfileNotice onopensettings={() => (panel = "settings")} />

  {#if daemon.lastError}
    <div class="error" role="alert">
      <p>{describeError(daemon.lastError)}</p>
      <button class="btn btn-text" type="button" onclick={() => daemon.dismissError()}>Dismiss</button>
    </div>
  {/if}

  <ProfileList
    profiles={daemon.profiles}
    statuses={daemon.statuses}
    busy={daemon.busy}
    available={daemon.available}
    onconnect={(id) => daemon.connect(id)}
    ondisconnect={(id) => daemon.disconnect(id)}
    onremove={(id) => daemon.remove(id)}
    onrename={(id, name) => daemon.rename(id, name)}
    onimport={() => (panel = "import")}
  />
</div>

{#if panel === "import"}
  <ImportDialog onclose={() => (panel = null)} />
{:else if panel === "settings"}
  <SettingsSheet
    profiles={daemon.profiles}
    logAvailable={daemon.available}
    onclose={() => (panel = null)}
    onopenlog={() => (panel = "log")}
    onopenlicenses={() => (panel = "licenses")}
  />
{:else if panel === "log"}
  <LogPanel onclose={() => (panel = null)} />
{:else if panel === "licenses"}
  <LicensesPanel onclose={() => (panel = null)} />
{/if}

{#if pending}
  {#key `${pending.profileId}:${pending.mode}`}
    <PinDialog profileId={pending.profileId} profileName={pendingName} mode={pending.mode} />
  {/key}
{/if}

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .error {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
    padding: 10px 8px 0 16px;
    color: var(--error);
  }

  .error p {
    padding-top: 4px;
  }

  .error .btn {
    color: var(--muted);
  }
</style>
