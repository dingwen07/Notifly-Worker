import { describe, expect, it } from "vitest";

import { base64Url, decodeBase64Url, sha256 } from "../src/crypto";

describe("crypto helpers", () => {
  it("round-trips base64url bytes without padding", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const encoded = base64Url(bytes);

    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    expect([...decodeBase64Url(encoded)]).toEqual([...bytes]);
  });

  it("hashes stable input as base64url", async () => {
    await expect(sha256("notifly")).resolves.toBe("8FqxIS_DEsVKd9J4bwjg3D4IRYtzW33b3hdWxMVY0MA");
  });
});
