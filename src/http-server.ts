#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import type { HttpBindings } from "@hono/node-server";
import { serve } from "@hono/node-server";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { type Context, Hono } from "hono";
import { createServer } from "./server.js";
import { verifyDokploySession } from "./utils/dokploySession.js";
import { createLogger } from "./utils/logger.js";
import { LightweightOAuthProvider, loadOAuthConfig, oauthMiddleware } from "./utils/oauth.js";

const PORT = 3000;
const logger = createLogger("MCP-HTTP-Server");

const jsonrpcError = (code: number, message: string) => ({
  jsonrpc: "2.0" as const,
  error: { code, message },
  id: null,
});

// When MCP transport takes over the raw Node response, we must prevent
// Hono/@hono/node-server from trying to write its own response headers.
// We return a Promise that NEVER resolves — the underlying Node response
// is already being handled by the MCP transport, so Hono must not touch it.
function neverResolve(): Promise<never> {
  return new Promise(() => {});
}

export async function main() {
  const app = new Hono<{ Bindings: HttpBindings }>();
  const oauth = new LightweightOAuthProvider(loadOAuthConfig());

  const transports = {
    streamable: {} as Record<string, StreamableHTTPServerTransport>,
    sse: {} as Record<string, SSEServerTransport>,
  };

  // Health check
  app.get("/health", (c) => c.json({ status: "ok", timestamp: new Date().toISOString() }));

  if (oauth.config.enabled) {
    const protectedResourceMetadata = {
      resource: oauth.config.resource,
      authorization_servers: [oauth.config.issuer],
      scopes_supported: ["mcp"],
    };
    app.get("/.well-known/oauth-protected-resource", (c) => c.json(protectedResourceMetadata));
    app.get("/.well-known/oauth-protected-resource/mcp", (c) =>
      c.json({
        ...protectedResourceMetadata,
      }),
    );
    app.get("/.well-known/oauth-authorization-server", (c) =>
      c.json({
        issuer: oauth.config.issuer,
        authorization_endpoint: `${oauth.config.issuer}/oauth/authorize`,
        token_endpoint: `${oauth.config.issuer}/oauth/token`,
        registration_endpoint: `${oauth.config.issuer}/oauth/register`,
        revocation_endpoint: `${oauth.config.issuer}/oauth/revoke`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["mcp"],
      }),
    );
    app.post("/oauth/register", async (c) => {
      try {
        const metadata = await c.req.json();
        if (
          metadata.token_endpoint_auth_method !== undefined &&
          metadata.token_endpoint_auth_method !== "none"
        ) {
          throw new Error(
            "Only public clients using token_endpoint_auth_method=none are supported",
          );
        }
        if (
          metadata.grant_types !== undefined &&
          (!Array.isArray(metadata.grant_types) ||
            metadata.grant_types.some((grant: unknown) => grant !== "authorization_code"))
        ) {
          throw new Error("Only the authorization_code grant is supported");
        }
        const client = oauth.register(metadata.redirect_uris);
        c.header("Cache-Control", "no-store");
        return c.json(
          {
            client_id: client.clientId,
            redirect_uris: client.redirectUris,
            token_endpoint_auth_method: "none",
            grant_types: ["authorization_code"],
            response_types: ["code"],
          },
          201,
        );
      } catch (error) {
        const description = String(error instanceof Error ? error.message : error);
        return c.json(
          {
            error: description.includes("redirect")
              ? "invalid_redirect_uri"
              : "invalid_client_metadata",
            error_description: description,
          },
          400,
        );
      }
    });
    app.get("/oauth/authorize", (c) => {
      const redirectUri = c.req.query("redirect_uri") ?? "";
      const state = c.req.query("state");
      c.header("Cache-Control", "no-store");
      c.header("Referrer-Policy", "no-referrer");
      try {
        if (
          c.req.query("response_type") !== "code" ||
          c.req.query("code_challenge_method") !== "S256"
        )
          throw new Error("Only authorization code with PKCE S256 is supported");
        if (!oauth.isClientRedirectUri(c.req.query("client_id") ?? "", redirectUri)) {
          throw new Error("Unknown client or unregistered redirect URI");
        }
        const pending = oauth.beginAuthorization({
          clientId: c.req.query("client_id") ?? "",
          redirectUri,
          codeChallenge: c.req.query("code_challenge") ?? "",
          resource: c.req.query("resource") ?? "",
          state,
        });
        const target = new URL(oauth.config.dokployBridgeUrl);
        target.searchParams.set("tx", pending.transactionId);
        target.searchParams.set("nonce", pending.nonce);
        return c.redirect(target.toString());
      } catch (error) {
        const message = error instanceof Error ? error.message : "Authorization failed";
        if (oauth.isClientRedirectUri(c.req.query("client_id") ?? "", redirectUri)) {
          return redirectOAuthError(c, redirectUri, state, "invalid_request", message);
        }
        return c.text(message, 400);
      }
    });
    app.get("/mcp-auth/verify", async (c) => {
      c.header("Cache-Control", "no-store");
      c.header("Referrer-Policy", "no-referrer");
      const transactionId = c.req.query("tx") ?? "";
      const nonce = c.req.query("nonce") ?? "";
      if (!oauth.hasPendingAuthorization(transactionId, nonce)) {
        return c.text("Invalid or expired Dokploy authorization transaction", 400);
      }

      try {
        const identity = await verifyDokploySession(
          oauth.config.dokploySessionUrl,
          c.req.header("cookie"),
        );
        if (!identity) {
          const continueUrl = new URL(oauth.config.dokployBridgeUrl);
          continueUrl.searchParams.set("tx", transactionId);
          continueUrl.searchParams.set("nonce", nonce);
          return dokploySignInPage(c, oauth.config.dokployLoginUrl, continueUrl.toString());
        }

        const result = oauth.completeAuthorization(transactionId, nonce, identity);
        const target = new URL(result.redirectUri);
        target.searchParams.set("code", result.code);
        if (result.state) target.searchParams.set("state", result.state);
        return c.redirect(target.toString());
      } catch (error) {
        if (error instanceof Error && error.message.includes("not allowed")) {
          return authorizationErrorPage(c, error.message, 403);
        }
        logger.error("Dokploy session verification failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return authorizationErrorPage(
          c,
          "Dokploy session verification is temporarily unavailable.",
          502,
        );
      }
    });
    app.post("/oauth/token", async (c) => {
      try {
        const form = await c.req.parseBody();
        if (form.grant_type !== "authorization_code") throw new Error("Unsupported grant type");
        const accessToken = oauth.exchangeCode({
          code: String(form.code ?? ""),
          clientId: String(form.client_id ?? ""),
          redirectUri: String(form.redirect_uri ?? ""),
          codeVerifier: String(form.code_verifier ?? ""),
          resource: String(form.resource ?? ""),
        });
        c.header("Cache-Control", "no-store");
        c.header("Pragma", "no-cache");
        return c.json({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 28800,
          scope: "mcp",
        });
      } catch (error) {
        return c.json(
          {
            error: "invalid_grant",
            error_description: error instanceof Error ? error.message : String(error),
          },
          400,
        );
      }
    });
    app.post("/oauth/revoke", async (c) => {
      const form = await c.req.parseBody();
      oauth.revoke(String(form.token ?? ""));
      c.header("Cache-Control", "no-store");
      return c.body(null, 200);
    });
    app.use("/mcp", oauthMiddleware(oauth));
    app.use("/sse", oauthMiddleware(oauth));
    app.use("/messages", oauthMiddleware(oauth));
  }

  // Modern Streamable HTTP - POST
  app.post("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    try {
      const sessionId = c.req.header("mcp-session-id");
      let transport: StreamableHTTPServerTransport;
      const body = await c.req.json();

      if (sessionId && transports.streamable[sessionId]) {
        transport = transports.streamable[sessionId];
      } else if (!sessionId && isInitializeRequest(body)) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid) => {
            transports.streamable[sid] = transport;
            logger.info("New MCP session initialized", { sessionId: sid });
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            logger.info("MCP session closed", { sessionId: transport.sessionId });
            delete transports.streamable[transport.sessionId];
          }
        };

        const server = createServer();
        await server.connect(
          transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport,
        );
      } else {
        return c.json(
          jsonrpcError(
            -32000,
            "Bad Request: No valid session ID or invalid initialization request",
          ),
          400,
        );
      }

      await transport.handleRequest(incoming, outgoing, body);
      return neverResolve();
    } catch (error) {
      logger.error("Error handling HTTP request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Modern Streamable HTTP - GET (SSE notifications)
  app.get("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    const sessionId = c.req.header("mcp-session-id");

    if (!sessionId || !transports.streamable[sessionId]) {
      return c.json(jsonrpcError(-32000, "Invalid or missing session ID"), 400);
    }

    try {
      const transport = transports.streamable[sessionId];
      await transport.handleRequest(incoming, outgoing);
      return neverResolve();
    } catch (error) {
      logger.error("Error handling GET request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Modern Streamable HTTP - DELETE (session termination)
  app.delete("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    const sessionId = c.req.header("mcp-session-id");

    if (!sessionId || !transports.streamable[sessionId]) {
      return c.json(jsonrpcError(-32000, "Invalid or missing session ID"), 400);
    }

    try {
      const transport = transports.streamable[sessionId];
      await transport.handleRequest(incoming, outgoing);

      if (transports.streamable[sessionId]) {
        logger.info("MCP session terminated", { sessionId });
        delete transports.streamable[sessionId];
      }
      return neverResolve();
    } catch (error) {
      logger.error("Error handling DELETE request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Legacy SSE endpoint
  app.get("/sse", async (c) => {
    const { outgoing } = c.env;
    try {
      const transport = new SSEServerTransport("/messages", outgoing);
      transports.sse[transport.sessionId] = transport;

      outgoing.on("close", () => {
        logger.info("Legacy SSE session closed", { sessionId: transport.sessionId });
        delete transports.sse[transport.sessionId];
      });

      const server = createServer();
      await server.connect(transport);
      logger.info("New legacy SSE session initialized", { sessionId: transport.sessionId });
      return neverResolve();
    } catch (error) {
      logger.error("Error handling SSE request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Legacy message endpoint
  app.post("/messages", async (c) => {
    const { incoming, outgoing } = c.env;
    try {
      const sessionId = c.req.query("sessionId");
      if (!sessionId) {
        return c.json(jsonrpcError(-32000, "sessionId query parameter is required"), 400);
      }

      const transport = transports.sse[sessionId];
      if (!transport) {
        return c.json(jsonrpcError(-32000, "No transport found for sessionId"), 400);
      }

      const body = await c.req.json();
      await transport.handlePostMessage(incoming, outgoing, body);
      return neverResolve();
    } catch (error) {
      logger.error("Error handling legacy message request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  serve({ fetch: app.fetch, port: PORT }, () => {
    logger.info("MCP Dokploy server started", {
      port: PORT,
      protocols: ["Streamable HTTP (MCP 2025-03-26)", "Legacy SSE (MCP 2024-11-05)"],
      endpoints: {
        modern: `http://localhost:${PORT}/mcp`,
        legacy: `http://localhost:${PORT}/sse`,
        health: `http://localhost:${PORT}/health`,
      },
      oauth: oauth.config.enabled ? "enabled" : "disabled",
    });
  });
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ??
      character,
  );
}

function authorizationErrorPage(c: Context, message: string, status: 400 | 401 | 403 | 502) {
  c.header("Cache-Control", "no-store");
  c.header(
    "Content-Security-Policy",
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  );
  return c.html(
    `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Dokploy authorization failed</title></head><body><main><h1>Dokploy authorization failed</h1><p>${escapeHtml(message)}</p></main></body></html>`,
    status,
  );
}

function dokploySignInPage(c: Context, loginUrl: string, continueUrl: string) {
  c.header("Cache-Control", "no-store");
  c.header("Referrer-Policy", "no-referrer");
  c.header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  );
  return c.html(
    `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Sign in to Dokploy</title><style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem}a{display:inline-block;margin:.5rem .75rem .5rem 0;padding:.7rem 1rem;border:1px solid;border-radius:.4rem}</style></head><body><main><h1>Sign in to Dokploy</h1><p>Open Dokploy and sign in in the same browser. When the Dokploy dashboard is visible, return to this page and continue.</p><a href="${escapeHtml(loginUrl)}" target="_blank" rel="noopener noreferrer">Open Dokploy sign-in</a><a href="${escapeHtml(continueUrl)}">Continue after sign-in</a></main></body></html>`,
    401,
  );
}

function redirectOAuthError(
  c: Context,
  redirectUri: string,
  state: string | undefined,
  error: string,
  description: string,
) {
  const target = new URL(redirectUri);
  target.searchParams.set("error", error);
  target.searchParams.set("error_description", description);
  if (state) target.searchParams.set("state", state);
  return c.redirect(target.toString());
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    logger.error("Fatal error occurred", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    process.exit(1);
  });
}
