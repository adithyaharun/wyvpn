<script lang="ts">
  import LoaderCircle from "@lucide/svelte/icons/loader-circle";
  import ShieldCheck from "@lucide/svelte/icons/shield-check";
  import ShieldOff from "@lucide/svelte/icons/shield-off";
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import { describeError } from "$lib/errors";
  import { formatBytes, formatUptime, stateLabel, transportLabel } from "$lib/format";
  import type { ConnectionStatus, ProfileSummary } from "$lib/types";
  import CopyButton from "./CopyButton.svelte";

  interface Props {
    session: ConnectionStatus | null;
    profile?: ProfileSummary;
  }

  let { session, profile }: Props = $props();

  let now = $state(Date.now());

  const current = $derived(session?.state ?? "disconnected");
  const tone = $derived(
    current === "connected"
      ? "connected"
      : current === "connecting" || current === "disconnecting"
        ? "transit"
        : current === "error"
          ? "error"
          : "idle",
  );
  const name = $derived(profile?.name || session?.profile_name || "");
  const endpoint = $derived(session?.server_endpoint || profile?.server_host || "Server");
  const tunnelIp = $derived(session?.tunnel_ip ?? null);
  const localIp = $derived(session?.local_ip ?? null);
  const since = $derived(current === "connected" ? (session?.connected_since ?? null) : null);
  const uptime = $derived(since === null ? "—" : formatUptime(now / 1000 - since));
  const error = $derived(session?.error ? describeError(session.error) : null);

  $effect(() => {
    if (since === null) return;
    now = Date.now();
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });
</script>

<section class="panel tone-{tone}" aria-label="Connection status">
  <p class="state" aria-live="polite">
    {#if tone === "connected"}
      <ShieldCheck class="glyph" size={22} strokeWidth={2} aria-hidden="true" />
    {:else if tone === "transit"}
      <LoaderCircle class="glyph spin" size={22} strokeWidth={2} aria-hidden="true" />
    {:else if tone === "error"}
      <TriangleAlert class="glyph" size={22} strokeWidth={2} aria-hidden="true" />
    {:else}
      <ShieldOff class="glyph" size={22} strokeWidth={2} aria-hidden="true" />
    {/if}
    {stateLabel(current)}
  </p>
  <p class="profile">
    {#if name}
      {name}
      {#if session?.transport}<span class="transport">{transportLabel(session.transport)}</span>{/if}
    {:else}
      <span class="muted">No active session</span>
    {/if}
  </p>

  <div class="link">
    <span class="end">This device</span>
    <span class="wire" aria-hidden="true"><span class="dot"></span><span class="line"></span><span class="dot"></span></span>
    <span class="end end-remote">
      <span class="num" title={endpoint}>{endpoint}</span>
      <span class="slot" class:empty={!session?.server_endpoint} aria-hidden={!session?.server_endpoint}>
        <CopyButton value={session?.server_endpoint ?? ""} label="Copy endpoint" disabled={!session?.server_endpoint} />
      </span>
    </span>
  </div>

  <dl class="details addresses">
    <div>
      <dt>Tunnel IP</dt>
      <dd>
        <span class="num">{tunnelIp ?? "—"}</span>
        <span class="slot" class:empty={!tunnelIp} aria-hidden={!tunnelIp}>
          <CopyButton value={tunnelIp ?? ""} label="Copy tunnel IP" disabled={!tunnelIp} />
        </span>
      </dd>
    </div>
    {#if localIp}
      <div>
        <dt>Local IP</dt>
        <dd>
          <span class="num">{localIp}</span>
          <CopyButton value={localIp} label="Copy local IP" />
        </dd>
      </div>
    {/if}
  </dl>

  <dl class="details counters">
    <div>
      <dt>Uptime</dt>
      <dd class="num">{uptime}</dd>
    </div>
    <div>
      <dt>Received</dt>
      <dd class="num">{formatBytes(session?.rx_bytes ?? 0)}</dd>
    </div>
    <div>
      <dt>Sent</dt>
      <dd class="num">{formatBytes(session?.tx_bytes ?? 0)}</dd>
    </div>
  </dl>

  <p class="alert" role="alert">{error ?? ""}</p>
</section>

<style>
  .panel {
    --tone: var(--ink);
    --wire: var(--line);
    display: grid;
    gap: 2px;
    padding: 8px 16px 14px;
    background: var(--surface);
    border-bottom: 1px solid var(--line);
  }

  .tone-connected {
    --tone: var(--connected);
    --wire: var(--connected);
  }

  .tone-transit {
    --tone: var(--connecting);
    --wire: var(--connecting);
  }

  .tone-error {
    --tone: var(--error);
  }

  .state {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--tone);
    font-size: 28px;
    font-weight: 650;
    letter-spacing: -0.02em;
    line-height: 1.1;
  }

  .tone-idle .state :global(.glyph) {
    color: var(--muted);
  }

  .profile {
    display: flex;
    align-items: baseline;
    gap: 8px;
    min-width: 0;
    font-size: 15px;
    font-weight: 550;
    overflow-wrap: anywhere;
  }

  .transport,
  .muted {
    color: var(--muted);
    font-size: 13px;
    font-weight: 400;
  }

  .link {
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    gap: 8px;
    margin: 12px 0 10px;
    color: var(--muted);
    font-size: 12px;
  }

  .end-remote {
    display: flex;
    align-items: center;
    gap: 2px;
    min-width: 0;
    max-width: 200px;
  }

  .end-remote .num {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .wire {
    display: flex;
    align-items: center;
    min-width: 24px;
  }

  .dot {
    flex: none;
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: var(--wire);
  }

  .line {
    flex: 1;
    height: 2px;
    background: var(--wire);
  }

  .tone-transit .line {
    position: relative;
    overflow: hidden;
    background: none;
  }

  .tone-transit .line::before {
    content: "";
    position: absolute;
    inset: 0 0 0 -12px;
    background: repeating-linear-gradient(90deg, var(--wire) 0 6px, transparent 6px 12px);
    will-change: transform;
    animation: travel 600ms linear infinite;
  }

  @keyframes travel {
    to {
      transform: translateX(12px);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .tone-transit .line::before {
      animation: none;
    }
  }

  .details {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px 16px;
    margin: 0;
  }

  .counters {
    grid-template-columns: repeat(3, 1fr);
    margin-top: 8px;
  }

  .details div {
    min-width: 0;
  }

  dt {
    color: var(--muted);
    font-size: 12px;
  }

  dd {
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .addresses dd {
    display: flex;
    align-items: center;
    gap: 2px;
    min-height: 22px;
  }

  .addresses .num {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .slot {
    display: inline-flex;
    flex: none;
  }

  .slot.empty {
    visibility: hidden;
  }

  .alert {
    min-height: 1.45em;
    margin-top: 8px;
    color: var(--error);
  }
</style>
