import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";

const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const CODE_TTL_MS = 5 * 60 * 1000;
const AUTHORIZATION_TTL_MS = 5 * 60 * 1000;
const MAX_EPHEMERAL_RECORDS = 1_000;

export interface OAuthConfig {
  enabled: boolean;
  issuer: string;
  resource: string;
  trustedRedirectUris: Set<string>;
  dokployPublicUrl: string;
  dokploySessionUrl: string;
  dokployLoginUrl: string;
  dokployBridgeUrl: string;
  allowedDokployUsers: Set<string>;
}

export interface DokployIdentity {
  id: string;
  email?: string | undefined;
  name?: string | undefined;
}

interface Client {
  clientId: string;
  redirectUris: string[];
}

interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  state?: string | undefined;
  codeChallenge: string;
  resource: string;
  nonceHash: string;
  expiresAt: number;
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
  private readonly pendingAuthorizations = new Map<string, PendingAuthorization>();
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

  beginAuthorization(input: {
    clientId: string;
    redirectUri: string;
    state?: string | undefined;
    codeChallenge: string;
    resource: string;
  }): { transactionId: string; nonce: string } {
    const redirectUri = normalizeRedirectUri(input.redirectUri);
    if (!this.isClientRedirectUri(input.clientId, redirectUri)) {
      throw new Error("Unknown client or unregistered redirect URI");
    }
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(input.codeChallenge)) {
      throw new Error("A valid PKCE S256 code_challenge is required");
    }
    if (input.resource !== this.config.resource) {
      throw new Error(`resource must be ${this.config.resource}`);
    }

    const transactionId = randomToken();
    const nonce = randomToken();
    this.pendingAuthorizations.set(transactionId, {
      clientId: input.clientId,
      redirectUri,
      state: input.state,
      codeChallenge: input.codeChallenge,
      resource: input.resource,
      nonceHash: hashToken(nonce),
      expiresAt: Date.now() + AUTHORIZATION_TTL_MS,
    });
    capMap(this.pendingAuthorizations);
    return { transactionId, nonce };
  }

  completeAuthorization(
    transactionId: string,
    nonce: string,
    identity: DokployIdentity,
  ): { code: string; redirectUri: string; state?: string | undefined } {
    const pending = this.pendingAuthorizations.get(transactionId);
    if (
      !pending ||
      pending.expiresAt < Date.now() ||
      !secretEquals(pending.nonceHash, hashToken(nonce))
    ) {
      throw new Error("Invalid or expired Dokploy authorization transaction");
    }
    if (!this.isAllowedIdentity(identity)) {
      throw new Error("This Dokploy user is not allowed to access the MCP server");
    }

    this.pendingAuthorizations.delete(transactionId);
    const code = randomToken();
    this.codes.set(code, {
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      resource: pending.resource,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    capMap(this.codes);
    return { code, redirectUri: pending.redirectUri, state: pending.state };
  }

  hasPendingAuthorization(transactionId: string, nonce: string): boolean {
    const pending = this.pendingAuthorizations.get(transactionId);
    return Boolean(
      pending &&
        pending.expiresAt >= Date.now() &&
        secretEquals(pending.nonceHash, hashToken(nonce)),
    );
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

  private isAllowedIdentity(identity: DokployIdentity): boolean {
    if (this.config.allowedDokployUsers.has("*")) return true;
    const candidates = [identity.id, identity.email?.toLowerCase()].filter(Boolean) as string[];
    return candidates.some((candidate) => this.config.allowedDokployUsers.has(candidate));
  }

  private isTrustedRedirectUri(redirectUri: string): boolean {
    const url = new URL(redirectUri);
    return (
      isLoopbackUrl(url) ||
      this.config.trustedRedirectUris.size === 0 ||
      this.config.trustedRedirectUris.has(redirectUri)
    );
  }
}

export function loadOAuthConfig(): OAuthConfig {
  const enabled = parseBoolean(process.env.MCP_OAUTH_ENABLED);
  const issuerUrl = normalizeOrigin(
    process.env.MCP_PUBLIC_URL ?? "http://localhost:3000",
    "MCP_PUBLIC_URL",
  );
  const issuer = issuerUrl.toString().replace(/\/$/, "");
  const resource = `${issuer}/mcp`;
  const dokployPublicUrl = normalizeOrigin(
    process.env.DOKPLOY_PUBLIC_URL ?? process.env.DOKPLOY_URL ?? "http://localhost:3000",
    "DOKPLOY_PUBLIC_URL",
    enabled,
  )
    .toString()
    .replace(/\/$/, "");
  const dokploySessionUrl = normalizeServiceUrl(
    nonEmpty(process.env.DOKPLOY_SESSION_URL) ??
      `${(process.env.DOKPLOY_URL ?? dokployPublicUrl).replace(/\/$/, "")}/api/user.session`,
    "DOKPLOY_SESSION_URL",
  );
  const dokployLoginUrl = normalizeServiceUrl(
    process.env.DOKPLOY_LOGIN_URL ?? `${dokployPublicUrl}/`,
    "DOKPLOY_LOGIN_URL",
  );
  const dokployBridgeUrl = normalizeServiceUrl(
    process.env.MCP_DOKPLOY_BRIDGE_URL ?? `${dokployPublicUrl}/mcp-auth/verify`,
    "MCP_DOKPLOY_BRIDGE_URL",
  );
  const allowedDokployUsers = new Set(
    splitList(process.env.MCP_ALLOWED_DOKPLOY_USERS).map((value) => value.toLowerCase()),
  );
  if (enabled && allowedDokployUsers.size === 0) {
    throw new Error("MCP_ALLOWED_DOKPLOY_USERS is required when MCP_OAUTH_ENABLED=true");
  }
  return {
    enabled,
    issuer,
    resource,
    trustedRedirectUris: new Set(
      splitList(process.env.MCP_OAUTH_TRUSTED_REDIRECT_URIS).map(normalizeRedirectUri),
    ),
    dokployPublicUrl,
    dokploySessionUrl,
    dokployLoginUrl,
    dokployBridgeUrl,
    allowedDokployUsers,
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

function normalizeOrigin(value: string, name: string, requireHttps = true): URL {
  const url = new URL(value);
  if (url.search || url.hash || url.username || url.password || url.pathname !== "/") {
    throw new Error(`${name} must be an origin without credentials, a path, query, or fragment`);
  }
  if (requireHttps && url.protocol !== "https:" && !isLoopbackUrl(url)) {
    throw new Error(`${name} must use HTTPS except on localhost or 127.0.0.1`);
  }
  return url;
}

function normalizeServiceUrl(value: string, name: string): string {
  const url = new URL(value);
  if (url.username || url.password || url.hash || !["http:", "https:"].includes(url.protocol)) {
    throw new Error(`${name} must be an HTTP(S) URL without credentials or a fragment`);
  }
  return url.toString();
}

function isLoopbackUrl(url: URL): boolean {
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function hashToken(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

function secretEquals(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function parseBoolean(value: string | undefined): boolean {
  return ["true", "1", "yes", "on"].includes(value?.trim().toLowerCase() ?? "");
}

function splitList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function nonEmpty(value: string | undefined): string | undefined {
  return value?.trim() || undefined;
}

function capMap<TKey, TValue>(map: Map<TKey, TValue>): void {
  while (map.size > MAX_EPHEMERAL_RECORDS) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) return;
    map.delete(oldest);
  }
}
