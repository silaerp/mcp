import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";

const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const CODE_TTL_MS = 5 * 60 * 1000;
const MAX_EPHEMERAL_RECORDS = 1_000;

export interface OAuthConfig {
  enabled: boolean;
  issuer: string;
  resource: string;
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
  resource: string;
  expiresAt: number;
}

export class LightweightOAuthProvider {
  private readonly clients = new Map<string, Client>();
  private readonly codes = new Map<string, AuthorizationCode>();
  private readonly tokens = new Map<string, { expiresAt: number; resource: string }>();

  constructor(readonly config: OAuthConfig) {}

  register(redirectUris: unknown): Client {
    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw new Error("redirect_uris must be a non-empty array");
    }
    const normalized = redirectUris.map((uri) => normalizeRedirectUri(uri));
    if (normalized.some((uri) => !this.isTrustedRedirectUri(uri))) {
      throw new Error(
        "HTTPS redirect URIs must be listed in MCP_OAUTH_TRUSTED_REDIRECT_URIS; loopback HTTP callbacks are allowed automatically",
      );
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
    resource: string;
    dokployApiKey: string;
  }): string {
    const redirectUri = normalizeRedirectUri(input.redirectUri);
    if (!this.isClientRedirectUri(input.clientId, redirectUri)) {
      throw new Error("Unknown client or unregistered redirect URI");
    }
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(input.codeChallenge)) {
      throw new Error("A valid PKCE S256 code_challenge is required");
    }
    if (!secretEquals(input.dokployApiKey, this.config.dokployApiKey)) {
      throw new Error("Invalid Dokploy API key");
    }
    if (input.resource !== this.config.resource) {
      throw new Error(`resource must be ${this.config.resource}`);
    }
    const code = randomToken();
    this.codes.set(code, {
      clientId: input.clientId,
      redirectUri,
      codeChallenge: input.codeChallenge,
      resource: input.resource,
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
    resource: string;
  }): string {
    const redirectUri = normalizeRedirectUri(input.redirectUri);
    const authorization = this.codes.get(input.code);
    const challenge = createHash("sha256").update(input.codeVerifier).digest("base64url");
    if (
      !authorization ||
      authorization.expiresAt < Date.now() ||
      authorization.clientId !== input.clientId ||
      authorization.redirectUri !== redirectUri ||
      authorization.resource !== input.resource ||
      input.resource !== this.config.resource ||
      !secretEquals(challenge, authorization.codeChallenge)
    ) {
      throw new Error("Invalid or expired authorization code");
    }
    this.codes.delete(input.code);
    const token = randomToken();
    this.tokens.set(token, { expiresAt: Date.now() + TOKEN_TTL_MS, resource: input.resource });
    capMap(this.tokens);
    return token;
  }

  verifyToken(token: string | undefined, resource = this.config.resource): boolean {
    if (!token) return false;
    const authorization = this.tokens.get(token);
    if (
      !authorization ||
      authorization.expiresAt < Date.now() ||
      authorization.resource !== resource
    ) {
      if (authorization) this.tokens.delete(token);
      return false;
    }
    return true;
  }

  revoke(token: string): void {
    this.tokens.delete(token);
  }

  isClientRedirectUri(clientId: string, redirectUri: string): boolean {
    try {
      const normalized = normalizeRedirectUri(redirectUri);
      return this.clients.get(clientId)?.redirectUris.includes(normalized) ?? false;
    } catch {
      return false;
    }
  }

  private isTrustedRedirectUri(redirectUri: string): boolean {
    const url = new URL(redirectUri);
    return isLoopbackUrl(url) || this.config.trustedRedirectUris.has(redirectUri);
  }
}

export function loadOAuthConfig(): OAuthConfig {
  const enabled = parseBoolean(process.env.MCP_OAUTH_ENABLED);
  const issuerUrl = normalizeIssuer(process.env.MCP_PUBLIC_URL ?? "http://localhost:3000");
  const issuer = issuerUrl.toString().replace(/\/$/, "");
  const resource = `${issuer}/mcp`;
  const trustedRedirectUris = new Set(
    (process.env.MCP_OAUTH_TRUSTED_REDIRECT_URIS ?? "")
      .split(",")
      .map((uri) => uri.trim())
      .filter(Boolean)
      .map(normalizeRedirectUri),
  );
  if (enabled && !process.env.DOKPLOY_API_KEY) {
    throw new Error("DOKPLOY_API_KEY is required when MCP_OAUTH_ENABLED=true");
  }
  return {
    enabled,
    issuer,
    resource,
    trustedRedirectUris,
    dokployApiKey: process.env.DOKPLOY_API_KEY ?? "",
  };
}

export function oauthMiddleware(provider: LightweightOAuthProvider): MiddlewareHandler {
  return async (c, next) => {
    const header = c.req.header("authorization");
    const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (provider.verifyToken(token, provider.config.resource)) return next();
    c.header(
      "WWW-Authenticate",
      `Bearer resource_metadata="${provider.config.issuer}/.well-known/oauth-protected-resource/mcp", scope="mcp"`,
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
  if (url.hash || (url.protocol !== "https:" && !isLoopbackUrl(url))) {
    throw new Error(
      "Redirect URIs must use HTTPS (localhost HTTP is allowed) and cannot contain fragments",
    );
  }
  return url.toString();
}

function normalizeIssuer(value: string): URL {
  const url = new URL(value);
  if (url.search || url.hash || url.username || url.password) {
    throw new Error("MCP_PUBLIC_URL cannot contain credentials, a query, or a fragment");
  }
  if (url.pathname !== "/") {
    throw new Error("MCP_PUBLIC_URL must be an origin without a path");
  }
  if (url.protocol !== "https:" && !isLoopbackUrl(url)) {
    throw new Error("MCP_PUBLIC_URL must use HTTPS except on localhost or 127.0.0.1");
  }
  return url;
}

function isLoopbackUrl(url: URL): boolean {
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
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
