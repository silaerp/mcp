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

  it("allows dynamic loopback ports for native MCP clients", () => {
    const oauth = provider();
    expect(oauth.register(["http://127.0.0.1:49152/callback"]).redirectUris).toEqual([
      "http://127.0.0.1:49152/callback",
    ]);
  });

  it("requires the configured Dokploy key and exchanges a PKCE code once", () => {
    const oauth = provider();
    const client = oauth.register([redirectUri]);
    expect(() =>
      oauth.createCode({
        clientId: client.clientId,
        redirectUri,
        codeChallenge: challenge,
        resource: "https://mcp.example/mcp",
        dokployApiKey: "wrong",
      }),
    ).toThrow("Invalid Dokploy API key");

    const code = oauth.createCode({
      clientId: client.clientId,
      redirectUri,
      codeChallenge: challenge,
      resource: "https://mcp.example/mcp",
      dokployApiKey: "dokploy-secret",
    });
    const token = oauth.exchangeCode({
      code,
      clientId: client.clientId,
      redirectUri,
      codeVerifier: verifier,
      resource: "https://mcp.example/mcp",
    });
    expect(oauth.verifyToken(token)).toBe(true);
    expect(() =>
      oauth.exchangeCode({
        code,
        clientId: client.clientId,
        redirectUri,
        codeVerifier: verifier,
        resource: "https://mcp.example/mcp",
      }),
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
      resource: "https://mcp.example/mcp",
      dokployApiKey: "dokploy-secret",
    });
    expect(() =>
      oauth.exchangeCode({
        code,
        clientId: client.clientId,
        redirectUri,
        codeVerifier: "b".repeat(43),
        resource: "https://mcp.example/mcp",
      }),
    ).toThrow("Invalid or expired authorization code");
    const token = oauth.exchangeCode({
      code,
      clientId: client.clientId,
      redirectUri,
      codeVerifier: verifier,
      resource: "https://mcp.example/mcp",
    });
    expect(oauth.verifyToken(token)).toBe(true);
  });

  it("binds authorization codes and tokens to the MCP resource", () => {
    const oauth = provider();
    const client = oauth.register([redirectUri]);
    expect(() =>
      oauth.createCode({
        clientId: client.clientId,
        redirectUri,
        codeChallenge: challenge,
        dokployApiKey: "dokploy-secret",
        resource: "https://other.example/mcp",
      }),
    ).toThrow("resource must be https://mcp.example/mcp");

    const code = oauth.createCode({
      clientId: client.clientId,
      redirectUri,
      codeChallenge: challenge,
      dokployApiKey: "dokploy-secret",
      resource: "https://mcp.example/mcp",
    });
    expect(() =>
      oauth.exchangeCode({
        code,
        clientId: client.clientId,
        redirectUri,
        codeVerifier: verifier,
        resource: "https://other.example/mcp",
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

  it("requires the Dokploy API key when enabled", () => {
    process.env.MCP_OAUTH_ENABLED = "true";
    delete process.env.DOKPLOY_API_KEY;
    expect(() => loadOAuthConfig()).toThrow("DOKPLOY_API_KEY is required");
  });

  it("rejects an insecure public OAuth issuer", () => {
    process.env.MCP_OAUTH_ENABLED = "true";
    process.env.DOKPLOY_API_KEY = "secret";
    process.env.MCP_PUBLIC_URL = "http://mcp.example";
    expect(() => loadOAuthConfig()).toThrow("MCP_PUBLIC_URL must use HTTPS");
  });
});
