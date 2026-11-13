<script lang="ts">
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { onMount } from "svelte";
  import DaemonIncompatible from "$lib/components/DaemonIncompatible.svelte";
  import DaemonNotPermitted from "$lib/components/DaemonNotPermitted.svelte";
  import DaemonOutdated from "$lib/components/DaemonOutdated.svelte";
  import DaemonSetup from "$lib/components/DaemonSetup.svelte";
  import DaemonStarting from "$lib/components/DaemonStarting.svelte";
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
  import UpdateSheet from "$lib/components/UpdateSheet.svelte";
  import WindowControls from "$lib/components/WindowControls.svelte";
  import { daemon, isActive } from "$lib/daemon.svelte";
  import { describeError } from "$lib/errors";
  import { PROMPT_CHANNEL, updates } from "$lib/update.svelte";
  import { detectPlatform, watchWindowChrome } from "$lib/window";
  import { drainWindowRequests } from "$lib/window-requests";

  type Panel = "import" | "settings" | "log" | "licenses";
  let panel = $state<Panel | null>(null);

  const session = $derived(daemon.session);
  const sessionProfile = $derived(daemon.profiles.find((p) => p.id === session?.profile_id));
  const pending = $derived(daemon.pendingCredentials);
  const vpnActive = $derived(
    pending !== null || Object.values(daemon.statuses).some((s) => isActive(s.state) || s.awaiting),
  );
  const pendingName = $derived(
    pending ? (daemon.profiles.find((p) => p.id === pending.profileId)?.name ?? "") : "",
  );

  const modal = $derived(panel !== null || pending !== null || updates.open);

  const platform = detectPlatform();
  if (platform !== "other") document.documentElement.dataset.platform = platform;

  onMount(() => {
    const stop = daemon.start();
    const stopUpdates = updates.start();
    const stopChrome = watchWindowChrome();
    const unlisteners: UnlistenFn[] = [];
    let disposed = false;
    const drain = () =>
      drainWindowRequests({
        licenses: () => {
          if (!disposed) panel = "licenses";
        },
        updatePrompt: () => {
          if (!disposed) updates.prompt();
        },
      });
    void Promise.allSettled([listen("app://open-licenses", drain), listen(PROMPT_CHANNEL, drain)]).then(
      (results) => {
        for (const result of results) {
          if (result.status !== "fulfilled") continue;
          if (disposed) result.value();
          else unlisteners.push(result.value);
        }
        if (!disposed) void drain();
      },
    );
    return () => {
      disposed = true;
      unlisteners.forEach((off) => off());
      stopChrome();
      stopUpdates();
      stop();
    };
  });
</script>

<div class="app" inert={modal}>
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
  {:else if daemon.status === "starting"}
    <DaemonStarting socket={daemon.socket} />
  {:else}
    <DaemonUnavailable socket={daemon.socket} />
  {/if}

  {#if daemon.available && daemon.mismatch}
    <DaemonOutdated mismatch={daemon.mismatch} />
  {/if}

  <DefaultProfileNotice onopensettings={() => (panel = "settings")} />

  {#if daemon.lastError}
    <div class="error" role="alert">
      <p class="selectable">{describeError(daemon.lastError)}</p>
      <button class="btn btn-text" type="button" onclick={() => daemon.dismissError()}>Dismiss</button>
    </div>
  {/if}

  <ProfileList
    profiles={daemon.profiles}
    statuses={daemon.statuses}
    busy={daemon.busy}
    available={daemon.available}
    onconnect={(id, transport) => daemon.connect(id, transport)}
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

{#if updates.open}
  <UpdateSheet {vpnActive} />
{/if}

{#if pending}
  {#key `${pending.profileId}:${pending.mode}`}
    <PinDialog profileId={pending.profileId} profileName={pendingName} mode={pending.mode} />
  {/key}
{/if}

{#if platform === "windows"}
  <WindowControls {modal} />
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
