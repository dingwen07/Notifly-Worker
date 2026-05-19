import { randomToken, sha256 } from "./crypto";
import { HttpError, jsonResponse, readJson, requireMethod } from "./http";
import { FcmSendError, sendFcmDataMessage, sendFcmRawData, verifyPlayIntegrity } from "./google";
import { ChallengeRecord, DeviceRecord, Env, FcmPriority, SendNotificationRequest, UserRecord } from "./types";

const CHALLENGE_TTL_SECONDS = 300;
const DAY_MS = 24 * 60 * 60 * 1000;
const INACTIVITY_STOP_DAYS = 7;
const INACTIVITY_DELETE_DAYS = 180;
const INTEGRITY_STALE_DAYS = 30;
const WAKE_INACTIVE_DAYS = 5;
const WAKE_INTEGRITY_DAYS = 15;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/health") {
        return jsonResponse({ ok: true });
      }
      if (url.pathname === "/v1/devices/integrity/challenge") {
        return await createChallenge(request, env);
      }
      if (url.pathname === "/v1/devices/integrity/reverify") {
        return await reverifyIntegrity(request, env);
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
  },

  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runDailyMaintenance(env));
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
    updatedAt: now,
    lastActiveAt: now,
    integrityVerifiedAt: now,
    inactive: false,
    fcmTokenInvalid: false
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
    registeredAt: record.registeredAt,
    lastActiveAt: record.lastActiveAt,
    integrityVerifiedAt: record.integrityVerifiedAt
  });
}

async function deviceStatus(request: Request, env: Env): Promise<Response> {
  requireMethod(request, "GET");
  const device = await authenticate(request, env);
  const now = new Date().toISOString();
  device.lastActiveAt = now;
  device.inactive = false;
  await env.NOTIFLY_KV.put(deviceKey(device.deviceId), JSON.stringify(device));
  return jsonResponse({
    registered: true,
    deviceId: device.deviceId,
    clientId: device.clientId,
    userId: device.userId,
    packageName: device.packageName,
    integrityVerdicts: device.integrityVerdicts,
    registeredAt: device.registeredAt,
    updatedAt: device.updatedAt,
    lastActiveAt: device.lastActiveAt,
    integrityVerifiedAt: device.integrityVerifiedAt,
    integrityStale: ageDays(device.integrityVerifiedAt) >= WAKE_INTEGRITY_DAYS,
    fcmTokenInvalid: device.fcmTokenInvalid === true
  });
}

async function reverifyIntegrity(request: Request, env: Env): Promise<Response> {
  requireMethod(request, "POST");
  const device = await authenticate(request, env);
  const body = await readJson<{ integrityToken?: string; nonce?: string }>(request);
  const integrityToken = requireString(body.integrityToken, "integrityToken");
  const nonce = requireString(body.nonce, "nonce");

  const challengeRaw = await env.NOTIFLY_KV.get(challengeKey(nonce));
  if (!challengeRaw) {
    throw new HttpError(401, "Challenge expired or unknown");
  }
  const challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  if (challenge.clientId !== device.clientId || challenge.expiresAt < Date.now()) {
    throw new HttpError(401, "Challenge mismatch");
  }

  const verdicts = await verifyPlayIntegrity(env, device.packageName, integrityToken, [nonce, await sha256(nonce)]);
  const now = new Date().toISOString();
  device.integrityVerdicts = verdicts;
  device.integrityVerifiedAt = now;
  device.lastActiveAt = now;
  device.inactive = false;
  await Promise.all([
    env.NOTIFLY_KV.put(deviceKey(device.deviceId), JSON.stringify(device)),
    env.NOTIFLY_KV.delete(challengeKey(nonce))
  ]);
  return jsonResponse({
    deviceId: device.deviceId,
    integrityVerdicts: verdicts,
    integrityVerifiedAt: device.integrityVerifiedAt,
    lastActiveAt: device.lastActiveAt
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

  const eligible: DeviceRecord[] = [];
  const skipped: { deviceId: string; reason: string }[] = [];
  for (const device of targets) {
    const reason = ineligibleReason(device);
    if (reason) skipped.push({ deviceId: device.deviceId, reason });
    else eligible.push(device);
  }

  const responses = await Promise.allSettled(
    eligible.map((device) => sendFcmDataMessage(env, device.fcmToken, notification, priority as FcmPriority))
  );

  await Promise.all(
    responses.map((result, index) => {
      if (result.status === "rejected" && result.reason instanceof FcmSendError && result.reason.tokenInvalid) {
        return markFcmTokenInvalid(env, eligible[index]);
      }
      return Promise.resolve();
    })
  );

  return jsonResponse({
    requested: targets.length,
    eligible: eligible.length,
    sent: responses.filter((result) => result.status === "fulfilled").length,
    skipped,
    failed: responses
      .map((result, index) => ({ result, deviceId: eligible[index].deviceId }))
      .filter((entry) => entry.result.status === "rejected")
      .map((entry) => ({
        deviceId: entry.deviceId,
        error: entry.result.status === "rejected" ? String(entry.result.reason) : undefined
      }))
  });
}

function ineligibleReason(device: DeviceRecord): string | undefined {
  if (device.fcmTokenInvalid) return "fcm_token_invalid";
  if (device.inactive) return "inactive";
  if (ageDays(device.lastActiveAt) >= INACTIVITY_STOP_DAYS) return "inactive";
  if (ageDays(device.integrityVerifiedAt) >= INTEGRITY_STALE_DAYS) return "integrity_stale";
  return undefined;
}

async function markFcmTokenInvalid(env: Env, device: DeviceRecord): Promise<void> {
  device.fcmTokenInvalid = true;
  await env.NOTIFLY_KV.put(deviceKey(device.deviceId), JSON.stringify(device));
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

async function runDailyMaintenance(env: Env): Promise<void> {
  let cursor: string | undefined;
  do {
    const page = await env.NOTIFLY_KV.list({ prefix: "device:", cursor });
    for (const entry of page.keys) {
      const raw = await env.NOTIFLY_KV.get(entry.name);
      if (!raw) continue;
      const device = JSON.parse(raw) as DeviceRecord;
      try {
        await processDeviceMaintenance(env, device);
      } catch (error) {
        console.log(`maintenance failed for ${device.deviceId}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

async function processDeviceMaintenance(env: Env, device: DeviceRecord): Promise<void> {
  const inactiveDays = ageDays(device.lastActiveAt);
  const integrityDays = ageDays(device.integrityVerifiedAt);

  if (inactiveDays >= INACTIVITY_DELETE_DAYS) {
    await deleteDevice(env, device);
    return;
  }

  if (inactiveDays >= INACTIVITY_STOP_DAYS && device.inactive !== true) {
    device.inactive = true;
    await env.NOTIFLY_KV.put(deviceKey(device.deviceId), JSON.stringify(device));
  }

  if (device.fcmTokenInvalid) return;

  const needsActivityWake = inactiveDays >= WAKE_INACTIVE_DAYS;
  const needsReverify = integrityDays >= WAKE_INTEGRITY_DAYS;
  if (!needsActivityWake && !needsReverify) return;

  const kind = needsReverify ? "reverify" : "wake";
  try {
    await sendFcmRawData(
      env,
      device.fcmToken,
      { notifly_kind: kind },
      "NORMAL"
    );
  } catch (error) {
    if (error instanceof FcmSendError && error.tokenInvalid) {
      await markFcmTokenInvalid(env, device);
    } else {
      throw error;
    }
  }
}

async function deleteDevice(env: Env, device: DeviceRecord): Promise<void> {
  const deletions: Promise<unknown>[] = [
    env.NOTIFLY_KV.delete(deviceKey(device.deviceId)),
    env.NOTIFLY_KV.delete(clientKey(device.clientId)),
    env.NOTIFLY_KV.delete(apiKeyLookupKey(device.apiKeyHash)),
    removeUserDevice(env, device.userId, device.deviceId)
  ];
  await Promise.all(deletions);
}

function ageDays(iso: string): number {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return Number.POSITIVE_INFINITY;
  return (Date.now() - t) / DAY_MS;
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
