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
  expectedNonces: string[]
): Promise<string[]> {
  if (env.DEV_SKIP_INTEGRITY === "true") {
    return ["DEV_SKIP_INTEGRITY"];
  }
  const enforceIntegrity = env.DEV_ENFORCE_INTEGRITY !== "false";

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
    const message = `Play Integrity rejected token: ${response.status} ${await response.text()}`;
    if (!enforceIntegrity) {
      console.log(message);
      return ["DEV_INTEGRITY_NOT_ENFORCED"];
    }
    throw new Error(message);
  }

  const decoded = await response.json<IntegrityDecodeResponse>();
  const payload = decoded.tokenPayloadExternal;
  if (env.DEV_LOG_INTEGRITY_VERDICT === "true") {
    console.log("Play Integrity verdict", JSON.stringify(payload));
  }
  const request = payload?.requestDetails;
  const app = payload?.appIntegrity;
  const deviceVerdicts = payload?.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  const account = payload?.accountDetails;

  if (request?.requestPackageName !== packageName || app?.packageName !== packageName) {
    return integrityFailure(enforceIntegrity, "Integrity token package name mismatch", deviceVerdicts);
  }
  const actualNonce = normalizeNonce(request?.nonce);
  const allowedNonces = expectedNonces.map(normalizeNonce);
  if (!actualNonce || !allowedNonces.includes(actualNonce)) {
    return integrityFailure(
      enforceIntegrity,
      `Integrity nonce mismatch: expected ${await describeNonces(expectedNonces)}, got ${await describeNonce(request?.nonce)}`,
      deviceVerdicts
    );
  }
  if (app?.appRecognitionVerdict !== "PLAY_RECOGNIZED") {
    return integrityFailure(enforceIntegrity, "App is not Play recognized", deviceVerdicts);
  }
  if (account?.appLicensingVerdict !== "LICENSED") {
    return integrityFailure(enforceIntegrity, "App licensing verdict is not licensed", deviceVerdicts);
  }
  if (!deviceVerdicts.includes("MEETS_STRONG_INTEGRITY")) {
    return integrityFailure(enforceIntegrity, "Device must meet strong integrity", deviceVerdicts);
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

async function describeNonce(nonce: string | undefined): Promise<string> {
  if (!nonce) {
    return "missing";
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce));
  const fingerprint = base64Url(new Uint8Array(digest)).slice(0, 12);
  return `len=${nonce.length} sha256=${fingerprint}`;
}

async function describeNonces(nonces: string[]): Promise<string> {
  return (await Promise.all(nonces.map((nonce) => describeNonce(nonce)))).join(" or ");
}

function normalizeNonce(nonce: string | undefined): string | undefined {
  return nonce?.replace(/=+$/g, "");
}

function integrityFailure(enforceIntegrity: boolean, message: string, verdicts: string[]): string[] {
  if (enforceIntegrity) {
    throw new Error(message);
  }
  console.log(message);
  return verdicts.length ? verdicts : ["DEV_INTEGRITY_NOT_ENFORCED"];
}
