<script lang="ts">
  import Bell from "@lucide/svelte/icons/bell";
  import BellOff from "@lucide/svelte/icons/bell-off";
  import Bug from "@lucide/svelte/icons/bug";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import Code from "@lucide/svelte/icons/code";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import Scale from "@lucide/svelte/icons/scale";
  import Info from "@lucide/svelte/icons/info";
  import Power from "@lucide/svelte/icons/power";
  import RefreshCw from "@lucide/svelte/icons/refresh-cw";
  import ScrollText from "@lucide/svelte/icons/scroll-text";
  import Star from "@lucide/svelte/icons/star";
  import { onMount } from "svelte";
  import { api } from "$lib/api";
  import { describeError, toCommandError } from "$lib/errors";
  import { formatAppVersion } from "$lib/format";
  import type { AppInfo, NotificationPermission, ProfileSummary, Settings, SupportTarget } from "$lib/types";
  import CopyButton from "./CopyButton.svelte";
  import Sheet from "./Sheet.svelte";

  interface Props {
    profiles: ProfileSummary[];
    logAvailable?: boolean;
    onclose: () => void;
    onopenlog: () => void;
    onopenlicenses?: () => void;
  }

  let { profiles, logAvailable = true, onclose, onopenlog, onopenlicenses }: Props = $props();

  const id = $props.id();
  let settings = $state<Settings | null>(null);
  let launchAtLogin = $state<boolean | null>(null);
  let permission = $state<NotificationPermission | null>(null);
  let saving = $state(false);
  let launchSaving = $state(false);
  let info = $state<AppInfo | null>(null);
  let error = $state<string | null>(null);

  const missingDefault = $derived(
    settings?.auto_connect_profile_id != null &&
      !profiles.some((p) => p.id === settings?.auto_connect_profile_id),
  );

  function fail(raw: unknown) {
    error = describeError(toCommandError(raw).toBody());
  }

  async function readPermission() {
    try {
      permission = await api.notificationPermission();
    } catch {
      permission = null;
    }
  }

  onMount(() => {
    api.getSettings().then((value) => (settings = value), fail);
    api.getLaunchAtLogin().then((value) => (launchAtLogin = value), fail);
    void readPermission();
    api.appInfo().then(
      (value) => (info = value ?? null),
      () => (info = null),
    );
  });

  async function openSupport(target: SupportTarget) {
    error = null;
    try {
      await api.openSupport(target);
    } catch {
      error = "WyVPN couldn't open your browser. Try again.";
    }
  }

  async function save(patch: Partial<Settings>) {
    if (!settings || saving) return;
    const previous = settings;
    settings = { ...previous, ...patch };
    saving = true;
    error = null;
    try {
      settings = await api.updateSettings(settings);
      if ("notifications" in patch) await readPermission();
    } catch (raw) {
      settings = previous;
      fail(raw);
    } finally {
      saving = false;
    }
  }

  async function toggleLaunch(event: Event) {
    const enabled = (event.currentTarget as HTMLInputElement).checked;
    const previous = launchAtLogin;
    launchAtLogin = enabled;
    launchSaving = true;
    error = null;
    try {
      launchAtLogin = await api.setLaunchAtLogin(enabled);
    } catch (raw) {
      launchAtLogin = previous;
      fail(raw);
    } finally {
      launchSaving = false;
    }
  }

  function pickDefault(event: Event) {
    const value = (event.currentTarget as HTMLSelectElement).value;
    void save({ auto_connect_profile_id: value || null });
  }
</script>

<Sheet title="Settings" size="full" {onclose}>
  <div class="settings">
    <div class="setting">
      <div class="text">
        <Power class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
        <label for="{id}-launch">Launch at login</label>
        <p class="help" id="{id}-launch-help">
          WyVPN starts in the tray when you sign in. Development builds register the development binary, not an
          installed app.
        </p>
      </div>
      <input
        id="{id}-launch"
        class="switch"
        type="checkbox"
        role="switch"
        aria-describedby="{id}-launch-help"
        checked={launchAtLogin ?? false}
        disabled={launchAtLogin === null || launchSaving}
        onchange={toggleLaunch}
      />
    </div>

    <div class="setting stacked">
      <div class="text">
        <Star class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
        <label for="{id}-default">Default profile</label>
        <p class="help" id="{id}-default-help">
          WyVPN connects to this profile once each time it starts. Profiles that need a PIN still ask for it.
        </p>
      </div>
      <select
        id="{id}-default"
        class="field"
        aria-describedby="{id}-default-help"
        value={settings?.auto_connect_profile_id ?? ""}
        disabled={!settings || saving}
        onchange={pickDefault}
      >
        <option value="">None</option>
        {#each profiles as profile (profile.id)}
          <option value={profile.id}>{profile.name}</option>
        {/each}
        {#if missingDefault}
          <option value={settings?.auto_connect_profile_id} disabled>Removed profile</option>
        {/if}
      </select>
      {#if missingDefault}
        <p class="help warn">The default profile was removed. Choose another profile or None.</p>
      {/if}
    </div>

    <div class="setting">
      <div class="text">
        <RefreshCw class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
        <label for="{id}-reconnect">Reconnect automatically</label>
        <p class="help" id="{id}-reconnect-help">
          When the connection drops or your network changes, WyVPN connects again.
        </p>
      </div>
      <input
        id="{id}-reconnect"
        class="switch"
        type="checkbox"
        role="switch"
        aria-describedby="{id}-reconnect-help"
        checked={settings?.auto_reconnect ?? false}
        disabled={!settings || saving}
        onchange={(event) => save({ auto_reconnect: event.currentTarget.checked })}
      />
    </div>

    <div class="setting">
      <div class="text">
        {#if settings?.notifications}
          <Bell class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
        {:else}
          <BellOff class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
        {/if}
        <label for="{id}-notify">Notifications</label>
        <p class="help" id="{id}-notify-help">
          Get notified when you connect or disconnect, when the connection drops, and when a PIN is needed.
        </p>
        {#if permission === "denied"}
          <p class="help warn" id="{id}-notify-blocked" role="status">
            Your system blocks notifications from WyVPN. Allow them in your system's notification settings.
          </p>
        {/if}
      </div>
      <input
        id="{id}-notify"
        class="switch"
        type="checkbox"
        role="switch"
        aria-describedby={permission === "denied" ? `${id}-notify-help ${id}-notify-blocked` : `${id}-notify-help`}
        checked={settings?.notifications ?? false}
        disabled={!settings || saving}
        onchange={(event) => save({ notifications: event.currentTarget.checked })}
      />
    </div>
  </div>

  {#if error}
    <p class="alert" role="alert">{error}</p>
  {/if}

  <section class="support" aria-labelledby="{id}-support">
    <h3 id="{id}-support">Support</h3>
    {#if info}
      <div class="row">
        <Info class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
        <div class="version">
          <p class="name">WyVPN {info.version}</p>
          <p class="help">{info.os} {info.arch}</p>
        </div>
        <CopyButton value={formatAppVersion(info)} label="Copy version" />
      </div>
    {/if}
    <button class="row link" type="button" onclick={() => openSupport("project")}>
      <Code class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
      <span class="name">GitHub project</span>
      <ExternalLink class="trail" size={14} strokeWidth={1.75} aria-hidden="true" />
    </button>
    <button class="row link" type="button" onclick={() => openSupport("issue")}>
      <Bug class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
      <span class="name">Report an issue</span>
      <ExternalLink class="trail" size={14} strokeWidth={1.75} aria-hidden="true" />
    </button>
    <button class="row link" type="button" disabled={!logAvailable} onclick={onopenlog}>
      <ScrollText class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
      <span class="name">Connection log</span>
      <ChevronRight class="trail" size={14} strokeWidth={1.75} aria-hidden="true" />
    </button>
    <button class="row link" type="button" onclick={() => onopenlicenses?.()}>
      <Scale class="glyph" size={14} strokeWidth={2} aria-hidden="true" />
      <span class="name">Third-party licenses</span>
      <ChevronRight class="trail" size={14} strokeWidth={1.75} aria-hidden="true" />
    </button>
  </section>
</Sheet>

<style>
  .settings {
    display: grid;
  }

  .setting {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: start;
    gap: 6px 16px;
    padding: 12px 0;
  }

  .setting:first-child {
    padding-top: 0;
  }

  .setting + .setting {
    border-top: 1px solid var(--line);
  }

  .stacked {
    grid-template-columns: 1fr;
  }

  .text {
    display: grid;
    grid-template-columns: 14px 1fr;
    column-gap: 8px;
    min-width: 0;
  }

  .text > :global(*) {
    grid-column: 2;
  }

  .text > :global(.glyph) {
    grid-column: 1;
    grid-row: 1;
    margin-top: 3px;
    color: var(--muted);
  }

  label {
    font-weight: 550;
  }

  .help {
    margin-top: 2px;
    color: var(--muted);
    font-size: 12px;
  }

  .warn {
    margin-top: 6px;
    color: var(--error);
  }

  select.field {
    appearance: none;
    padding-right: 28px;
    background-image:
      linear-gradient(45deg, transparent 50%, var(--muted) 50%),
      linear-gradient(135deg, var(--muted) 50%, transparent 50%);
    background-position:
      right 14px center,
      right 10px center;
    background-size: 4px 4px;
    background-repeat: no-repeat;
    font: inherit;
    color: inherit;
  }

  .switch {
    appearance: none;
    position: relative;
    flex: none;
    width: 32px;
    height: 18px;
    margin: 1px 0 0;
    border-radius: 9px;
    background: color-mix(in srgb, var(--muted) 75%, var(--surface));
    cursor: pointer;
    transition: background-color 140ms ease-out;
  }

  .switch::after {
    content: "";
    position: absolute;
    top: 2px;
    left: 2px;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--surface);
    box-shadow: 0 1px 2px rgb(0 0 0 / 0.2);
    transition: transform 140ms cubic-bezier(0.2, 0.8, 0.2, 1);
  }

  .switch:checked {
    background: var(--ink);
  }

  .switch:checked::after {
    transform: translateX(14px);
  }

  .switch:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .alert {
    margin-top: 4px;
  }

  .support {
    display: grid;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--line);
  }

  h3 {
    margin-bottom: 4px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 550;
  }

  .row {
    display: grid;
    grid-template-columns: 14px 1fr auto;
    align-items: center;
    column-gap: 8px;
    min-height: 32px;
    margin: 0 -8px;
    padding: 6px 8px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    text-align: left;
  }

  .row > :global(.glyph) {
    color: var(--muted);
  }

  .row > :global(.trail) {
    color: var(--muted);
  }

  .version {
    min-width: 0;
  }

  .version .help {
    margin-top: 0;
  }

  .name {
    font-weight: 550;
  }

  .link {
    cursor: pointer;
  }

  .link:not(:disabled):hover {
    background: var(--hover);
  }

  .link:disabled {
    opacity: 0.45;
    cursor: default;
  }


  @media (prefers-reduced-motion: reduce) {
    .switch,
    .switch::after {
      transition: none;
    }
  }
</style>
