import { randomToken, sha256 } from "./crypto";
import { HttpError, jsonResponse, readJson, requireMethod } from "./http";
import { sendFcmDataMessage, verifyPlayIntegrity } from "./google";
import { ChallengeRecord, DeviceRecord, Env, FcmPriority, SendNotificationRequest, UserRecord } from "./types";

const CHALLENGE_TTL_SECONDS = 300;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/health") {
        return jsonResponse({ ok: true });
      }
      if (url.pathname === "/v1/integrity/challenge") {
        return await createChallenge(request, env);
      }
      if (url.pathname === "/v1/devices/register") {
        return await registerDevice(request, env);
      }
      if (url.pathname === "/v1/devices/status") {
        return await deviceStatus(request, env);
      }
      if (url.pathname === "/v1/notifications/send") {
        return await sendNotification(request, env);
      }
      return jsonResponse({ error: "Not found" }, { status: 404 });
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse({ error: error.message }, { status: error.status });
      }
      return jsonResponse(
        { error: error instanceof Error ? error.message : "Internal server error" },
        { status: 500 }
      );
    }
  }
};

async function createChallenge(request: Request, env: Env): Promise<Response> {
  requireMethod(request, "POST");
  const body = await readJson<{ clientId?: string }>(request);
  const clientId = requireString(body.clientId, "clientId");
  const nonce = randomToken(32);
  const expiresAt = Date.now() + CHALLENGE_TTL_SECONDS * 1000;
  const record: ChallengeRecord = { clientId, nonce, expiresAt };
  await env.NOTIFLY_KV.put(challengeKey(nonce), JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS
  });
  return jsonResponse({ nonce, expiresAt: new Date(expiresAt).toISOString() });
}

async function registerDevice(request: Request, env: Env): Promise<Response> {
  requireMethod(request, "POST");
  const body = await readJson<{
    clientId?: string;
    fcmToken?: string;
    packageName?: string;
    integrityToken?: string;
    nonce?: string;
    userId?: string;
    userKey?: string;
  }>(request);

  const clientId = requireString(body.clientId, "clientId");
  const fcmToken = requireString(body.fcmToken, "fcmToken");
  const packageName = requireString(body.packageName, "packageName");
  const integrityToken = requireString(body.integrityToken, "integrityToken");
  const nonce = requireString(body.nonce, "nonce");

  if (packageName !== env.ANDROID_PACKAGE_NAME) {
    throw new HttpError(400, "Unexpected packageName");
  }

  const challengeRaw = await env.NOTIFLY_KV.get(challengeKey(nonce));
  if (!challengeRaw) {
    throw new HttpError(401, "Challenge expired or unknown");
  }
  const challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  if (challenge.clientId !== clientId || challenge.expiresAt < Date.now()) {
    throw new HttpError(401, "Challenge mismatch");
  }

  const integrityVerdicts = await verifyPlayIntegrity(env, packageName, integrityToken, [nonce, await sha256(nonce)]);
  const userCredentials = await resolveUser(env, body.userId, body.userKey);
  const existingDeviceId = await env.NOTIFLY_KV.get(clientKey(clientId));
  const deviceId = existingDeviceId ?? randomToken(18);
  const apiKey = randomToken(32);
  const now = new Date().toISOString();
  const existingRaw = await env.NOTIFLY_KV.get(deviceKey(deviceId));
  const existing = existingRaw ? (JSON.parse(existingRaw) as DeviceRecord) : undefined;
  const record: DeviceRecord = {
    deviceId,
    clientId,
    userId: userCredentials.userId,
    fcmToken,
    apiKeyHash: await sha256(apiKey),
    packageName,
    integrityVerdicts,
    registeredAt: existing?.registeredAt ?? now,
    updatedAt: now
  };

  const writes: Promise<unknown>[] = [
    env.NOTIFLY_KV.put(deviceKey(deviceId), JSON.stringify(record)),
    env.NOTIFLY_KV.put(clientKey(clientId), deviceId),
    env.NOTIFLY_KV.put(apiKeyLookupKey(await sha256(apiKey)), deviceId),
    env.NOTIFLY_KV.put(userRecordKey(userCredentials.userId), JSON.stringify(userCredentials.record)),
    addUserDevice(env, userCredentials.userId, deviceId),
    env.NOTIFLY_KV.delete(challengeKey(nonce))
  ];
  if (existing?.apiKeyHash) {
    writes.push(env.NOTIFLY_KV.delete(apiKeyLookupKey(existing.apiKeyHash)));
  }
  if (existing?.userId && existing.userId !== userCredentials.userId) {
    writes.push(removeUserDevice(env, existing.userId, deviceId));
  }
  await Promise.all(writes);

  return jsonResponse({
    deviceId,
    apiKey,
    userId: userCredentials.userId,
    userKey: userCredentials.userKey,
    registeredAt: record.registeredAt
  });
}

async function deviceStatus(request: Request, env: Env): Promise<Response> {
  requireMethod(request, "GET");
  const device = await authenticate(request, env);
  return jsonResponse({
    registered: true,
    deviceId: device.deviceId,
    clientId: device.clientId,
    userId: device.userId,
    packageName: device.packageName,
    integrityVerdicts: device.integrityVerdicts,
    registeredAt: device.registeredAt,
    updatedAt: device.updatedAt
  });
}

async function sendNotification(request: Request, env: Env): Promise<Response> {
  requireMethod(request, "POST");
  const caller = await authenticate(request, env);
  const body = await readJson<SendNotificationRequest>(request);
  const notification = body.notification;
  if (!notification?.title || !notification.body) {
    throw new HttpError(400, "notification.title and notification.body are required");
  }
  if (notification.buttons && notification.buttons.length > 3) {
    throw new HttpError(400, "Android notifications support up to 3 action buttons");
  }

  const priority = body.fcmPriority ?? env.DEFAULT_FCM_PRIORITY ?? "HIGH";
  if (priority !== "NORMAL" && priority !== "HIGH") {
    throw new HttpError(400, "fcmPriority must be NORMAL or HIGH");
  }

  const targets = await resolveTargets(env, caller, body.deviceIds, body.clientIds, body.allUserDevices);
  if (targets.length === 0) {
    throw new HttpError(404, "No target devices found");
  }

  const responses = await Promise.allSettled(
    targets.map((device) => sendFcmDataMessage(env, device.fcmToken, notification, priority as FcmPriority))
  );

  return jsonResponse({
    requested: targets.length,
    sent: responses.filter((result) => result.status === "fulfilled").length,
    failed: responses
      .map((result, index) => ({ result, deviceId: targets[index].deviceId }))
      .filter((entry) => entry.result.status === "rejected")
      .map((entry) => ({
        deviceId: entry.deviceId,
        error: entry.result.status === "rejected" ? String(entry.result.reason) : undefined
      }))
  });
}

async function authenticate(request: Request, env: Env): Promise<DeviceRecord> {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) {
    throw new HttpError(401, "Missing bearer API key");
  }
  const keyHash = await sha256(match[1]);
  const deviceId = await env.NOTIFLY_KV.get(apiKeyLookupKey(keyHash));
  if (!deviceId) {
    throw new HttpError(401, "Invalid API key");
  }
  const rawDevice = await env.NOTIFLY_KV.get(deviceKey(deviceId));
  if (!rawDevice) {
    throw new HttpError(401, "Device no longer exists");
  }
  return JSON.parse(rawDevice) as DeviceRecord;
}

async function resolveTargets(
  env: Env,
  caller: DeviceRecord,
  deviceIds: string[] | undefined,
  clientIds: string[] | undefined,
  allUserDevices: boolean | undefined
): Promise<DeviceRecord[]> {
  const requestedDeviceIds = new Set(deviceIds?.length ? deviceIds : [caller.deviceId]);
  for (const clientId of clientIds ?? []) {
    const deviceId = await env.NOTIFLY_KV.get(clientKey(clientId));
    if (deviceId) requestedDeviceIds.add(deviceId);
  }
  if (allUserDevices) {
    const userDeviceIds = await getUserDeviceIds(env, caller.userId);
    userDeviceIds.forEach((deviceId) => requestedDeviceIds.add(deviceId));
  }
  const devices = await Promise.all([...requestedDeviceIds].map((id) => env.NOTIFLY_KV.get(deviceKey(id))));
  return devices.filter(Boolean).map((raw) => JSON.parse(raw as string) as DeviceRecord);
}

async function resolveUser(
  env: Env,
  requestedUserId: string | undefined,
  requestedUserKey: string | undefined
): Promise<{ userId: string; userKey: string; record: UserRecord }> {
  if (requestedUserId && requestedUserKey) {
    const raw = await env.NOTIFLY_KV.get(userRecordKey(requestedUserId));
    if (raw) {
      const record = JSON.parse(raw) as UserRecord;
      if (record.userKeyHash === await sha256(requestedUserKey)) {
        return { userId: record.userId, userKey: requestedUserKey, record };
      }
    }
  }

  const userId = randomToken(18);
  const userKey = randomToken(32);
  return {
    userId,
    userKey,
    record: {
      userId,
      userKeyHash: await sha256(userKey),
      createdAt: new Date().toISOString()
    }
  };
}

async function addUserDevice(env: Env, userId: string, deviceId: string): Promise<void> {
  const deviceIds = new Set(await getUserDeviceIds(env, userId));
  deviceIds.add(deviceId);
  await env.NOTIFLY_KV.put(userDevicesKey(userId), JSON.stringify([...deviceIds]));
}

async function removeUserDevice(env: Env, userId: string, deviceId: string): Promise<void> {
  const deviceIds = (await getUserDeviceIds(env, userId)).filter((id) => id !== deviceId);
  await env.NOTIFLY_KV.put(userDevicesKey(userId), JSON.stringify(deviceIds));
}

async function getUserDeviceIds(env: Env, userId: string): Promise<string[]> {
  const raw = await env.NOTIFLY_KV.get(userDevicesKey(userId));
  return raw ? (JSON.parse(raw) as string[]) : [];
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new HttpError(400, `${name} is required`);
  }
  return value.trim();
}

function challengeKey(nonce: string): string {
  return `challenge:${nonce}`;
}

function deviceKey(deviceId: string): string {
  return `device:${deviceId}`;
}

function clientKey(clientId: string): string {
  return `client:${clientId}`;
}

function userRecordKey(userId: string): string {
  return `user:${userId}`;
}

function userDevicesKey(userId: string): string {
  return `user-devices:${userId}`;
}

function apiKeyLookupKey(apiKeyHash: string): string {
  return `api-key:${apiKeyHash}`;
}
