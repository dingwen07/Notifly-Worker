export interface Env {
  NOTIFLY_KV: KVNamespace;
  ANDROID_PACKAGE_NAME: string;
  DEFAULT_FCM_PRIORITY?: "NORMAL" | "HIGH";
  GOOGLE_SERVICE_ACCOUNT_JSON?: string;
  GOOGLE_SERVICE_ACCOUNT_KEY_JSON_BASE64?: string;
  DEV_SKIP_INTEGRITY?: string;
  DEV_SKIP_FCM?: string;
}

export type FcmPriority = "NORMAL" | "HIGH";

export interface ChallengeRecord {
  clientId: string;
  nonce: string;
  expiresAt: number;
}

export interface DeviceRecord {
  deviceId: string;
  clientId: string;
  fcmToken: string;
  apiKeyHash: string;
  packageName: string;
  integrityVerdicts: string[];
  registeredAt: string;
  updatedAt: string;
}

export interface ApiAction {
  label?: string;
  type: "open_uri" | "intent" | "activity" | "broadcast";
  uri?: string;
  intentAction?: string;
  activityClass?: string;
  extras?: Record<string, string>;
}

export interface NotificationPayload {
  title: string;
  body: string;
  channelId?: string;
  clickAction?: ApiAction;
  buttons?: ApiAction[];
  tag?: string;
}

export interface SendNotificationRequest {
  deviceIds?: string[];
  clientIds?: string[];
  notification: NotificationPayload;
  fcmPriority?: FcmPriority;
}
