import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";

const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const CODE_TTL_MS = 5 * 60 * 1000;
const MAX_EPHEMERAL_RECORDS = 1_000;

export interface OAuthConfig {
  enabled: boolean;
  issuer: string;
  trustedRedirectUris: Set<string>;
  dokployApiKey: string;
}

interface Client {
  clientId: string;
  redirectUris: string[];
}

interface AuthorizationCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
}

export class LightweightOAuthProvider {
  private readonly clients = new Map<string, Client>();
  private readonly codes = new Map<string, AuthorizationCode>();
  private readonly tokens = new Map<string, number>();

  constructor(readonly config: OAuthConfig) {}

  register(redirectUris: unknown): Client {
    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw new Error("redirect_uris must be a non-empty array");
    }
    const normalized = redirectUris.map((uri) => normalizeRedirectUri(uri));
    if (normalized.some((uri) => !this.config.trustedRedirectUris.has(uri))) {
      throw new Error("Every redirect URI must be listed in MCP_OAUTH_TRUSTED_REDIRECT_URIS");
    }
    const client = { clientId: randomToken(), redirectUris: normalized };
    this.clients.set(client.clientId, client);
    capMap(this.clients);
    return client;
  }

  createCode(input: {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    dokployApiKey: string;
  }): string {
    const redirectUri = normalizeRedirectUri(input.redirectUri);
    const client = this.clients.get(input.clientId);
    if (!client?.redirectUris.includes(redirectUri)) {
      throw new Error("Unknown client or unregistered redirect URI");
    }
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(input.codeChallenge)) {
      throw new Error("A valid PKCE S256 code_challenge is required");
    }
    if (!secretEquals(input.dokployApiKey, this.config.dokployApiKey)) {
      throw new Error("Invalid Dokploy API key");
    }
    const code = randomToken();
    this.codes.set(code, {
      clientId: input.clientId,
      redirectUri,
      codeChallenge: input.codeChallenge,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    capMap(this.codes);
    return code;
  }

  exchangeCode(input: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier: string;
  }): string {
    const redirectUri = normalizeRedirectUri(input.redirectUri);
    const authorization = this.codes.get(input.code);
    this.codes.delete(input.code);
    const challenge = createHash("sha256").update(input.codeVerifier).digest("base64url");
    if (
      !authorization ||
      authorization.expiresAt < Date.now() ||
      authorization.clientId !== input.clientId ||
      authorization.redirectUri !== redirectUri ||
      !secretEquals(challenge, authorization.codeChallenge)
    ) {
      throw new Error("Invalid or expired authorization code");
    }
    const token = randomToken();
    this.tokens.set(token, Date.now() + TOKEN_TTL_MS);
    capMap(this.tokens);
    return token;
  }

  verifyToken(token: string | undefined): boolean {
    if (!token) return false;
    const expiresAt = this.tokens.get(token);
    if (!expiresAt || expiresAt < Date.now()) {
      if (expiresAt) this.tokens.delete(token);
      return false;
    }
    return true;
  }

  revoke(token: string): void {
    this.tokens.delete(token);
  }
}

export function loadOAuthConfig(): OAuthConfig {
  const enabled = parseBoolean(process.env.MCP_OAUTH_ENABLED);
  const issuer = (process.env.MCP_PUBLIC_URL ?? "http://localhost:3000").replace(/\/$/, "");
  const trustedRedirectUris = new Set(
    (process.env.MCP_OAUTH_TRUSTED_REDIRECT_URIS ?? "")
      .split(",")
      .map((uri) => uri.trim())
      .filter(Boolean)
      .map(normalizeRedirectUri),
  );
  if (enabled && trustedRedirectUris.size === 0) {
    throw new Error("MCP_OAUTH_TRUSTED_REDIRECT_URIS is required when MCP_OAUTH_ENABLED=true");
  }
  if (enabled && !process.env.DOKPLOY_API_KEY) {
    throw new Error("DOKPLOY_API_KEY is required when MCP_OAUTH_ENABLED=true");
  }
  return {
    enabled,
    issuer,
    trustedRedirectUris,
    dokployApiKey: process.env.DOKPLOY_API_KEY ?? "",
  };
}

export function oauthMiddleware(provider: LightweightOAuthProvider): MiddlewareHandler {
  return async (c, next) => {
    const header = c.req.header("authorization");
    const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (provider.verifyToken(token)) return next();
    c.header(
      "WWW-Authenticate",
      `Bearer resource_metadata="${provider.config.issuer}/.well-known/oauth-protected-resource/mcp"`,
    );
    return c.json(
      { error: "unauthorized", error_description: "A valid OAuth access token is required" },
      401,
    );
  };
}

function normalizeRedirectUri(value: unknown): string {
  if (typeof value !== "string") throw new Error("Redirect URIs must be strings");
  const url = new URL(value);
  if (
    url.hash ||
    (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1")
  ) {
    throw new Error(
      "Redirect URIs must use HTTPS (localhost HTTP is allowed) and cannot contain fragments",
    );
  }
  return url.toString();
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function secretEquals(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function parseBoolean(value: string | undefined): boolean {
  return ["true", "1", "yes", "on"].includes(value?.trim().toLowerCase() ?? "");
}

function capMap<TKey, TValue>(map: Map<TKey, TValue>): void {
  while (map.size > MAX_EPHEMERAL_RECORDS) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) return;
    map.delete(oldest);
  }
}
