import { decodeBase64Url } from "./crypto";
import { Env, FcmPriority, NotificationPayload } from "./types";

interface ServiceAccount {
  client_email: string;
  private_key: string;
  project_id: string;
}

interface IntegrityDecodeResponse {
  tokenPayloadExternal?: {
    requestDetails?: {
      requestPackageName?: string;
      nonce?: string;
      timestampMillis?: string;
    };
    appIntegrity?: {
      appRecognitionVerdict?: string;
      packageName?: string;
      certificateSha256Digest?: string[];
      versionCode?: string;
    };
    deviceIntegrity?: {
      deviceRecognitionVerdict?: string[];
    };
    accountDetails?: {
      appLicensingVerdict?: string;
    };
  };
}

let cachedToken: { accessToken: string; expiresAt: number } | undefined;

export async function verifyPlayIntegrity(
  env: Env,
  packageName: string,
  integrityToken: string,
  expectedNonceHash: string
): Promise<string[]> {
  if (env.DEV_SKIP_INTEGRITY === "true") {
    return ["DEV_SKIP_INTEGRITY"];
  }

  const accessToken = await getGoogleAccessToken(env);
  const url = `https://playintegrity.googleapis.com/v1/${packageName}:decodeIntegrityToken`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ integrityToken })
  });

  if (!response.ok) {
    throw new Error(`Play Integrity rejected token: ${response.status} ${await response.text()}`);
  }

  const decoded = await response.json<IntegrityDecodeResponse>();
  const payload = decoded.tokenPayloadExternal;
  const request = payload?.requestDetails;
  const app = payload?.appIntegrity;
  const deviceVerdicts = payload?.deviceIntegrity?.deviceRecognitionVerdict ?? [];

  if (request?.requestPackageName !== packageName || app?.packageName !== packageName) {
    throw new Error("Integrity token package name mismatch");
  }
  if (request?.nonce !== expectedNonceHash) {
    throw new Error("Integrity nonce mismatch");
  }
  if (app?.appRecognitionVerdict !== "PLAY_RECOGNIZED") {
    throw new Error("App is not Play recognized");
  }
  if (!deviceVerdicts.some((verdict) => verdict === "MEETS_DEVICE_INTEGRITY" || verdict === "MEETS_STRONG_INTEGRITY")) {
    throw new Error("Device integrity verdict is insufficient");
  }

  return deviceVerdicts;
}

export async function sendFcmDataMessage(
  env: Env,
  token: string,
  payload: NotificationPayload,
  priority: FcmPriority
): Promise<unknown> {
  if (env.DEV_SKIP_FCM === "true") {
    return {
      name: "dev/mock-message",
      tokenPreview: `${token.slice(0, 8)}...`,
      priority,
      payload
    };
  }

  const serviceAccount = getServiceAccount(env);
  const accessToken = await getGoogleAccessToken(env);
  const response = await fetch(`https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      message: {
        token,
        android: {
          priority
        },
        data: {
          notifly_payload: JSON.stringify(payload)
        }
      }
    })
  });

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`FCM send failed: ${response.status} ${body}`);
  }
  return body ? JSON.parse(body) : {};
}

async function getGoogleAccessToken(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.expiresAt - 60 > now) {
    return cachedToken.accessToken;
  }

  const serviceAccount = getServiceAccount(env);
  const assertion = await createJwt(serviceAccount, now);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });

  if (!response.ok) {
    throw new Error(`Google OAuth failed: ${response.status} ${await response.text()}`);
  }

  const token = await response.json<{ access_token: string; expires_in: number }>();
  cachedToken = {
    accessToken: token.access_token,
    expiresAt: now + token.expires_in
  };
  return token.access_token;
}

function getServiceAccount(env: Env): ServiceAccount {
  if (env.GOOGLE_SERVICE_ACCOUNT_KEY_JSON_BASE64) {
    return JSON.parse(atob(env.GOOGLE_SERVICE_ACCOUNT_KEY_JSON_BASE64)) as ServiceAccount;
  }
  if (env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    return JSON.parse(env.GOOGLE_SERVICE_ACCOUNT_JSON) as ServiceAccount;
  }
  throw new Error("GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_KEY_JSON_BASE64 is required");
}

async function createJwt(serviceAccount: ServiceAccount, now: number): Promise<string> {
  const header = base64Json({ alg: "RS256", typ: "JWT" });
  const claim = base64Json({
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/playintegrity",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  });
  const signingInput = `${header}.${claim}`;
  const key = await importPrivateKey(serviceAccount.private_key);
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const body = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  return crypto.subtle.importKey(
    "pkcs8",
    decodeBase64Url(body),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

function base64Json(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
