import { invoke, type InvokeArgs } from "@tauri-apps/api/core";
import { toCommandError } from "./errors";
import type {
  AppInfo,
  ConnectionStatus,
  DaemonAvailability,
  NotificationPermission,
  OpenVpnNotice,
  ProfileSummary,
  SessionLog,
  ServiceStatus,
  Settings,
  StartupNotice,
  SupportTarget,
  Transport,
} from "./types";

async function call<T>(command: string, args?: InvokeArgs): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw toCommandError(error);
  }
}

export const api = {
  daemonState: () => call<DaemonAvailability>("daemon_state"),
  listProfiles: () => call<ProfileSummary[]>("list_profiles"),
  status: () => call<ConnectionStatus[]>("status"),
  importFile: (replace: boolean) => call<ProfileSummary[] | null>("import_file", { replace }),
  importLink: (link: string, replace: boolean) =>
    call<ProfileSummary[]>("import_link", { link, replace }),
  replaceImport: (retry: string) => call<ProfileSummary[]>("replace_import", { retry }),
  removeProfile: (profileId: string) => call<null>("remove_profile", { profileId }),
  connect: (profileId: string, transport?: Transport) =>
    call<null>("connect", transport ? { profileId, transport } : { profileId }),
  submitPin: (profileId: string, pin: string) => call<null>("submit_pin", { profileId, pin }),
  cancelCredentials: (profileId: string) => call<null>("cancel_credentials", { profileId }),
  disconnect: (profileId: string) => call<null>("disconnect", { profileId }),
  renameProfile: (profileId: string, name: string) =>
    call<ProfileSummary>("rename_profile", { profileId, name }),
  sessionLog: () => call<SessionLog>("session_log"),
  getSettings: () => call<Settings>("get_settings"),
  updateSettings: (settings: Settings) => call<Settings>("update_settings", { settings }),
  notificationPermission: () => call<NotificationPermission>("notification_permission"),
  getLaunchAtLogin: () => call<boolean>("get_launch_at_login"),
  setLaunchAtLogin: (enabled: boolean) => call<boolean>("set_launch_at_login", { enabled }),
  takeStartupNotice: () => call<StartupNotice | null>("take_startup_notice"),
  appInfo: () => call<AppInfo>("app_info"),
  serviceStatus: () => call<ServiceStatus | null>("service_status"),
  registerService: () => call<ServiceStatus>("register_service"),
  repairService: () => call<ServiceStatus>("repair_service"),
  serviceReapproval: () => call<boolean>("service_reapproval"),
  serviceError: () => call<string | null>("service_error"),
  openLoginItems: () => call<null>("open_login_items"),
  thirdPartyLicenses: () => call<string>("third_party_licenses"),
  openvpnNotice: () => call<OpenVpnNotice>("openvpn_notice"),
  openSupport: (target: SupportTarget) => call<null>("open_support", { target }),
};
