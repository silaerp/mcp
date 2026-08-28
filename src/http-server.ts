#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import type { HttpBindings } from "@hono/node-server";
import { serve } from "@hono/node-server";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { Hono } from "hono";
import { createServer } from "./server.js";
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
      resource: `${oauth.config.issuer}/mcp`,
      authorization_servers: [oauth.config.issuer],
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
      }),
    );
    app.post("/oauth/register", async (c) => {
      try {
        const client = oauth.register((await c.req.json()).redirect_uris);
        return c.json(
          {
            client_id: client.clientId,
            redirect_uris: client.redirectUris,
            token_endpoint_auth_method: "none",
          },
          201,
        );
      } catch (error) {
        return c.json(
          {
            error: "invalid_redirect_uri",
            error_description: String(error instanceof Error ? error.message : error),
          },
          400,
        );
      }
    });
    app.get("/oauth/authorize", (c) => {
      const query = new URLSearchParams(c.req.query()).toString();
      return c.html(
        `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Dokploy login</title></head><body><main><h1>Sign in with Dokploy</h1><p>Enter the API key for this Dokploy MCP deployment. It is checked in constant time and is never stored.</p><form method="post" action="/oauth/authorize?${escapeHtml(query)}"><label>Dokploy API key <input name="dokploy_api_key" type="password" required autocomplete="off"></label><button type="submit">Authorize</button></form></main></body></html>`,
      );
    });
    app.post("/oauth/authorize", async (c) => {
      const redirectUri = c.req.query("redirect_uri") ?? "";
      const state = c.req.query("state");
      try {
        if (
          c.req.query("response_type") !== "code" ||
          c.req.query("code_challenge_method") !== "S256"
        )
          throw new Error("Only authorization code with PKCE S256 is supported");
        const form = await c.req.parseBody();
        const code = oauth.createCode({
          clientId: c.req.query("client_id") ?? "",
          redirectUri,
          codeChallenge: c.req.query("code_challenge") ?? "",
          dokployApiKey: String(form.dokploy_api_key ?? ""),
        });
        const target = new URL(redirectUri);
        target.searchParams.set("code", code);
        if (state) target.searchParams.set("state", state);
        return c.redirect(target.toString());
      } catch (error) {
        return c.text(error instanceof Error ? error.message : "Authorization failed", 400);
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
        });
        return c.json({ access_token: accessToken, token_type: "Bearer", expires_in: 28800 });
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

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    logger.error("Fatal error occurred", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    process.exit(1);
  });
}
