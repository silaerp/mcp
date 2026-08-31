import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { LightweightOAuthProvider, loadOAuthConfig } from "./oauth.js";

const redirectUri = "https://client.example/callback";
const verifier = "a".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");

function provider() {
  return new LightweightOAuthProvider({
    enabled: true,
    issuer: "https://mcp.example",
    resource: "https://mcp.example/mcp",
    trustedRedirectUris: new Set([redirectUri]),
    dokployPublicUrl: "https://dokploy.example",
    dokploySessionUrl: "http://dokploy:3000/api/user.session",
    dokployLoginUrl: "https://dokploy.example/",
    dokployBridgeUrl: "https://dokploy.example/mcp-auth/verify",
    allowedDokployUsers: new Set(["user-1", "admin@example.com"]),
  });
}

function authorization(oauth: LightweightOAuthProvider) {
  const client = oauth.register([redirectUri]);
  const pending = oauth.beginAuthorization({
    clientId: client.clientId,
    redirectUri,
    codeChallenge: challenge,
    resource: "https://mcp.example/mcp",
    state: "client-state",
  });
  return { client, pending };
}

describe("LightweightOAuthProvider", () => {
  it("registers only explicitly trusted redirect URIs", () => {
    const oauth = provider();
    expect(oauth.register([redirectUri]).redirectUris).toEqual([redirectUri]);
    expect(() => oauth.register(["https://evil.example/callback"])).toThrow(
      "MCP_OAUTH_TRUSTED_REDIRECT_URIS",
    );
  });

  it("allows hosted dynamic registration when no callback allowlist is configured", () => {
    const oauth = provider();
    oauth.config.trustedRedirectUris.clear();
    expect(oauth.register(["https://chatgpt.com/connector/callback"]).redirectUris).toEqual([
      "https://chatgpt.com/connector/callback",
    ]);
  });

  it("allows dynamic loopback ports for native MCP clients", () => {
    expect(provider().register(["http://127.0.0.1:49152/callback"]).redirectUris).toEqual([
      "http://127.0.0.1:49152/callback",
    ]);
  });

  it("binds a Dokploy login transaction and exchanges its PKCE code once", () => {
    const oauth = provider();
    const { client, pending } = authorization(oauth);
    expect(oauth.hasPendingAuthorization(pending.transactionId, pending.nonce)).toBe(true);
    expect(oauth.hasPendingAuthorization(pending.transactionId, "wrong")).toBe(false);

    const completed = oauth.completeAuthorization(pending.transactionId, pending.nonce, {
      id: "user-1",
    });
    expect(completed).toMatchObject({ redirectUri, state: "client-state" });
    expect(() =>
      oauth.completeAuthorization(pending.transactionId, pending.nonce, { id: "user-1" }),
    ).toThrow("Invalid or expired");

    const token = oauth.exchangeCode({
      code: completed.code,
      clientId: client.clientId,
      redirectUri,
      codeVerifier: verifier,
      resource: "https://mcp.example/mcp",
    });
    expect(oauth.verifyToken(token)).toBe(true);
    expect(() =>
      oauth.exchangeCode({
        code: completed.code,
        clientId: client.clientId,
        redirectUri,
        codeVerifier: verifier,
        resource: "https://mcp.example/mcp",
      }),
    ).toThrow("Invalid or expired authorization code");
  });

  it("rejects users outside the explicit allowlist without consuming the transaction", () => {
    const oauth = provider();
    const { pending } = authorization(oauth);
    expect(() =>
      oauth.completeAuthorization(pending.transactionId, pending.nonce, {
        id: "other",
        email: "other@example.com",
      }),
    ).toThrow("not allowed");
    expect(
      oauth.completeAuthorization(pending.transactionId, pending.nonce, {
        id: "other",
        email: "ADMIN@example.com",
      }).code,
    ).toBeTruthy();
  });

  it("supports an explicit wildcard for deployments that trust every Dokploy user", () => {
    const oauth = provider();
    oauth.config.allowedDokployUsers = new Set(["*"]);
    const { pending } = authorization(oauth);
    expect(
      oauth.completeAuthorization(pending.transactionId, pending.nonce, { id: "any-user" }).code,
    ).toBeTruthy();
  });

  it("rejects a bad PKCE verifier and a mismatched resource", () => {
    const oauth = provider();
    const { client, pending } = authorization(oauth);
    const { code } = oauth.completeAuthorization(pending.transactionId, pending.nonce, {
      id: "user-1",
    });
    expect(() =>
      oauth.exchangeCode({
        code,
        clientId: client.clientId,
        redirectUri,
        codeVerifier: "b".repeat(43),
        resource: "https://mcp.example/mcp",
      }),
    ).toThrow("Invalid or expired");
    expect(() =>
      oauth.exchangeCode({
        code,
        clientId: client.clientId,
        redirectUri,
        codeVerifier: verifier,
        resource: "https://other.example/mcp",
      }),
    ).toThrow("Invalid or expired");
  });
});

describe("loadOAuthConfig", () => {
  const oldEnvironment = { ...process.env };
  afterEach(() => {
    process.env = { ...oldEnvironment };
  });

  it("is disabled by default", () => {
    delete process.env.MCP_OAUTH_ENABLED;
    expect(loadOAuthConfig().enabled).toBe(false);
  });

  it("requires an explicit user allowlist when enabled", () => {
    process.env.MCP_OAUTH_ENABLED = "true";
    delete process.env.MCP_ALLOWED_DOKPLOY_USERS;
    expect(() => loadOAuthConfig()).toThrow("MCP_ALLOWED_DOKPLOY_USERS is required");
  });

  it("loads the Dokploy bridge endpoints", () => {
    process.env.MCP_OAUTH_ENABLED = "true";
    process.env.MCP_ALLOWED_DOKPLOY_USERS = "USER-1, Admin@Example.com";
    process.env.MCP_PUBLIC_URL = "https://mcp.example";
    process.env.DOKPLOY_PUBLIC_URL = "https://dokploy.example";
    process.env.DOKPLOY_URL = "http://dokploy:3000";
    const config = loadOAuthConfig();
    expect(config.dokploySessionUrl).toBe("http://dokploy:3000/api/user.session");
    expect(config.dokployBridgeUrl).toBe("https://dokploy.example/mcp-auth/verify");
    expect(config.allowedDokployUsers).toEqual(new Set(["user-1", "admin@example.com"]));
  });

  it("rejects an insecure public OAuth issuer", () => {
    process.env.MCP_OAUTH_ENABLED = "true";
    process.env.MCP_ALLOWED_DOKPLOY_USERS = "user-1";
    process.env.MCP_PUBLIC_URL = "http://mcp.example";
    expect(() => loadOAuthConfig()).toThrow("MCP_PUBLIC_URL must use HTTPS");
  });
});
