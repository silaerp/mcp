import { afterEach, describe, expect, it, vi } from "vitest";
import { extractIdentity, verifyDokploySession } from "./dokploySession.js";

describe("Dokploy session verification", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("extracts identities from common Dokploy session response shapes", () => {
    expect(extractIdentity({ user: { id: "user-1", email: "ADMIN@EXAMPLE.COM" } })).toEqual({
      id: "user-1",
      email: "admin@example.com",
      name: undefined,
    });
    expect(extractIdentity({ session: { user: { userId: "user-2", name: "Admin" } } })).toEqual({
      id: "user-2",
      email: undefined,
      name: "Admin",
    });
  });

  it("forwards only the browser cookie to the fixed session URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ user: { id: "user-1" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      verifyDokploySession("http://dokploy:3000/api/user.session", "session=secret"),
    ).resolves.toEqual({ id: "user-1", email: undefined, name: undefined });
    expect(fetchMock).toHaveBeenCalledWith(
      "http://dokploy:3000/api/user.session",
      expect.objectContaining({
        headers: { Accept: "application/json", Cookie: "session=secret" },
        redirect: "manual",
      }),
    );
  });

  it("treats missing, rejected, and redirected sessions as unauthenticated", async () => {
    await expect(verifyDokploySession("http://dokploy/session", undefined)).resolves.toBeNull();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 401 })));
    await expect(verifyDokploySession("http://dokploy/session", "session=bad")).resolves.toBeNull();
  });
});
