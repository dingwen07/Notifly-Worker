import { describe, expect, it } from "vitest";

import worker from "../src/index";
import { Env } from "../src/types";

describe("worker error handling", () => {
  it("returns JSON errors for async registration failures", async () => {
    const nonce = "test-nonce";
    const env = {
      ANDROID_PACKAGE_NAME: "net.extrawdw.notifly",
      NOTIFLY_KV: {
        get: async (key: string) =>
          key === `challenge:${nonce}`
            ? JSON.stringify({
                clientId: "test-client",
                nonce,
                expiresAt: Date.now() + 60_000
              })
            : null,
        put: async () => undefined,
        delete: async () => undefined
      }
    } as unknown as Env;

    const response = await worker.fetch(
      new Request("https://notifly.example/v1/devices/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          clientId: "test-client",
          fcmToken: "fake-token",
          packageName: "net.extrawdw.notifly",
          integrityToken: "fake-integrity-token",
          nonce
        })
      }),
      env
    );

    await expect(response.json()).resolves.toEqual({
      error: "GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_KEY_JSON_BASE64 is required"
    });
    expect(response.status).toBe(500);
    expect(response.headers.get("content-type")).toContain("application/json");
  });
});
