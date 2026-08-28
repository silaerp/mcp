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
    trustedRedirectUris: new Set([redirectUri]),
    dokployApiKey: "dokploy-secret",
  });
}

describe("LightweightOAuthProvider", () => {
  it("registers only explicitly trusted redirect URIs", () => {
    const oauth = provider();
    expect(oauth.register([redirectUri]).redirectUris).toEqual([redirectUri]);
    expect(() => oauth.register(["https://evil.example/callback"])).toThrow(
      "MCP_OAUTH_TRUSTED_REDIRECT_URIS",
    );
  });

  it("requires the configured Dokploy key and exchanges a PKCE code once", () => {
    const oauth = provider();
    const client = oauth.register([redirectUri]);
    expect(() =>
      oauth.createCode({
        clientId: client.clientId,
        redirectUri,
        codeChallenge: challenge,
        dokployApiKey: "wrong",
      }),
    ).toThrow("Invalid Dokploy API key");

    const code = oauth.createCode({
      clientId: client.clientId,
      redirectUri,
      codeChallenge: challenge,
      dokployApiKey: "dokploy-secret",
    });
    const token = oauth.exchangeCode({
      code,
      clientId: client.clientId,
      redirectUri,
      codeVerifier: verifier,
    });
    expect(oauth.verifyToken(token)).toBe(true);
    expect(() =>
      oauth.exchangeCode({ code, clientId: client.clientId, redirectUri, codeVerifier: verifier }),
    ).toThrow("Invalid or expired authorization code");
    oauth.revoke(token);
    expect(oauth.verifyToken(token)).toBe(false);
  });

  it("rejects a bad PKCE verifier", () => {
    const oauth = provider();
    const client = oauth.register([redirectUri]);
    const code = oauth.createCode({
      clientId: client.clientId,
      redirectUri,
      codeChallenge: challenge,
      dokployApiKey: "dokploy-secret",
    });
    expect(() =>
      oauth.exchangeCode({
        code,
        clientId: client.clientId,
        redirectUri,
        codeVerifier: "b".repeat(43),
      }),
    ).toThrow("Invalid or expired authorization code");
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

  it("requires a trusted redirect URI when enabled", () => {
    process.env.MCP_OAUTH_ENABLED = "true";
    delete process.env.MCP_OAUTH_TRUSTED_REDIRECT_URIS;
    expect(() => loadOAuthConfig()).toThrow("MCP_OAUTH_TRUSTED_REDIRECT_URIS is required");
  });
});
