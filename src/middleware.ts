// Hono-native ports of the three middleware that ship with
// @modelcontextprotocol/sdk's auth router:
//
//   - allowedMethods: 405 gate
//   - authenticateClient: client_secret_post for token/revoke endpoints
//   - requireBearerAuth: resource-server bearer validation
//
// Wire shape (status codes, header names, response bodies) is
// preserved exactly. Three behavioral changes:
//
//   1. Hono Context replaces Express Request/Response.
//   2. `c.var.client` (client-authenticated) and `c.var.auth`
//      (bearer-authenticated) replace `req.client` / `req.auth`.
//   3. We also recognize Authorization: Basic for client_secret_basic.
//      The SDK's clientAuth doesn't — but most strict clients (and our
//      own users) expect it, and RFC 6749 §2.3.1 prefers Basic.

import type { Context, MiddlewareHandler } from 'hono'
import { z } from 'zod'
import type { OAuthRegisteredClientsStore, OAuthTokenVerifier } from './provider'
import type { OAuthClientInformationFull } from './schemas'
import type { AuthInfo } from './types'
import {
  InsufficientScopeError,
  InvalidClientError,
  InvalidRequestError,
  InvalidTokenError,
  OAuthError,
  ServerError,
} from './errors'

/**
 * Hono Variables interface — middleware in this file sets these.
 * Consumers can refer to them via Hono's typed context generic.
 *
 *     const app = new Hono<{ Variables: McpOauthVars }>()
 */
export type McpOauthVars = {
  client: OAuthClientInformationFull
  auth: AuthInfo
}

// ---- error response helper ------------------------------------------

/** Common JSON-error responder. Spec-strict clients (e.g. Anthropic's
 *  connector backend) match on exact `error` codes, so we emit the
 *  shape the SDK does: plain `application/json`, no charset. */
function oauthErrorResponse(err: unknown, defaultStatus = 400): Response {
  if (err instanceof OAuthError) {
    const status = err instanceof ServerError ? 500 : defaultStatus
    return new Response(JSON.stringify(err.toResponseObject()), {
      status,
      headers: { 'content-type': 'application/json' },
    })
  }
  const se = new ServerError('Internal Server Error')
  return new Response(JSON.stringify(se.toResponseObject()), {
    status: 500,
    headers: { 'content-type': 'application/json' },
  })
}

// ---- allowedMethods --------------------------------------------------

/** 405 gate. Mirrors the SDK's allowedMethods middleware: returns
 *  the OAuth `method_not_allowed` error body plus an `Allow` header. */
export function allowedMethods(methods: string[]): MiddlewareHandler {
  const allow = methods.join(', ')
  return async (c, next) => {
    if (methods.includes(c.req.method)) return next()
    return new Response(
      JSON.stringify({
        error: 'method_not_allowed',
        error_description: `The method ${c.req.method} is not allowed for this endpoint`,
      }),
      {
        status: 405,
        headers: { 'content-type': 'application/json', allow },
      },
    )
  }
}

// ---- authenticateClient ---------------------------------------------

const ClientAuthFormSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().optional(),
})

/** Parse Authorization: Basic <b64(id:secret)>. RFC 6749 §2.3.1 says
 *  this is the PREFERRED way for confidential clients. The SDK's stock
 *  middleware only reads from the body — we accept both. */
function parseBasicAuth(header: string | undefined): {
  clientId?: string
  clientSecret?: string
} {
  if (!header) return {}
  const lower = header.trim().toLowerCase()
  if (!lower.startsWith('basic ')) return {}
  try {
    const decoded = atob(header.trim().slice(6).trim())
    const idx = decoded.indexOf(':')
    if (idx < 0) return {}
    return {
      clientId: decodeURIComponent(decoded.slice(0, idx)),
      clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
    }
  } catch {
    return {}
  }
}

/**
 * Middleware for endpoints that need client authentication
 * (`/token`, `/revoke`). Mirrors the SDK's `authenticateClient` and
 * attaches the resolved client to `c.var.client`.
 *
 * Important: the SDK compares `client.client_secret === request_secret`
 * — i.e. plaintext-vs-plaintext. Providers that store hashed secrets
 * must hash incoming secrets BEFORE the body reaches this middleware
 * (a one-line `c.req` body shim in the consumer's app). The SDK takes
 * the same stance.
 */
export function authenticateClient(opts: {
  clientsStore: OAuthRegisteredClientsStore
}): MiddlewareHandler<{ Variables: McpOauthVars }> {
  return async (c, next) => {
    try {
      // Body shape (form or JSON; the consumer parses it before us).
      const body = (await readFormOrJson(c)) as Record<string, unknown>

      // Try Basic auth first. RFC 6749 §2.3.1 — server "SHOULD" support
      // it; many clients prefer it over body-based credentials.
      const basic = parseBasicAuth(c.req.header('authorization'))

      const parsed = ClientAuthFormSchema.safeParse({
        client_id: basic.clientId ?? body.client_id,
        client_secret: basic.clientSecret ?? body.client_secret,
      })
      if (!parsed.success) {
        throw new InvalidRequestError(String(parsed.error))
      }

      const { client_id, client_secret } = parsed.data
      const client = await opts.clientsStore.getClient(client_id)
      if (!client) throw new InvalidClientError('Invalid client_id')

      if (client.client_secret) {
        if (!client_secret) throw new InvalidClientError('Client secret is required')
        if (client.client_secret !== client_secret) {
          throw new InvalidClientError('Invalid client_secret')
        }
        if (
          client.client_secret_expires_at &&
          client.client_secret_expires_at < Math.floor(Date.now() / 1000)
        ) {
          throw new InvalidClientError('Client secret has expired')
        }
      }
      // Stash the body too, so downstream handlers don't have to re-parse.
      c.set('client', client)
      ;(c as Context & { __body?: unknown }).__body = body
      return next()
    } catch (err) {
      // RFC 6749 §5.2: invalid_client → 401. Other client errors → 400.
      if (err instanceof InvalidClientError) {
        return new Response(JSON.stringify(err.toResponseObject()), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        })
      }
      return oauthErrorResponse(err)
    }
  }
}

/**
 * Body shim used by handlers downstream of authenticateClient — returns
 * the body the middleware already parsed, or parses fresh if we got
 * here some other way. Form-encoded and JSON both supported.
 */
export async function readFormOrJson(
  c: Context,
): Promise<Record<string, unknown>> {
  const cached = (c as Context & { __body?: Record<string, unknown> }).__body
  if (cached) return cached
  const ct = (c.req.header('content-type') || '').toLowerCase()
  try {
    if (ct.includes('application/json')) {
      return (await c.req.json()) as Record<string, unknown>
    }
    if (ct.includes('application/x-www-form-urlencoded')) {
      const text = await c.req.text()
      const params = new URLSearchParams(text)
      const obj: Record<string, unknown> = {}
      params.forEach((v, k) => {
        obj[k] = v
      })
      return obj
    }
    // Fallback: try to parse as both — clients in the wild do both.
    const text = await c.req.text()
    try {
      return JSON.parse(text) as Record<string, unknown>
    } catch {
      const params = new URLSearchParams(text)
      const obj: Record<string, unknown> = {}
      params.forEach((v, k) => {
        obj[k] = v
      })
      return obj
    }
  } catch {
    return {}
  }
}

// ---- requireBearerAuth ----------------------------------------------

/** Build a spec-compliant WWW-Authenticate header. RFC 9728 §5.1
 *  adds the `resource_metadata` field so MCP clients can discover
 *  the auth server from a 401. */
function buildWwwAuthHeader(
  errorCode: string,
  message: string,
  requiredScopes: string[],
  resourceMetadataUrl?: string,
): string {
  let header = `Bearer error="${errorCode}", error_description="${message}"`
  if (requiredScopes.length > 0) header += `, scope="${requiredScopes.join(' ')}"`
  if (resourceMetadataUrl) header += `, resource_metadata="${resourceMetadataUrl}"`
  return header
}

/** Middleware for resource-server endpoints (e.g. `/api/mcp`).
 *  Validates the bearer token via the provider, optionally enforces
 *  scopes, attaches AuthInfo to `c.var.auth`, and on failure emits a
 *  spec-compliant 401/403 with the right WWW-Authenticate header. */
export function requireBearerAuth(opts: {
  verifier: OAuthTokenVerifier
  requiredScopes?: string[]
  /** URL of the PRM document for this resource. Per RFC 9728 §5.1,
   *  including this lets MCP clients auto-discover the AS from a 401. */
  resourceMetadataUrl?: string
}): MiddlewareHandler<{ Variables: McpOauthVars }> {
  const requiredScopes = opts.requiredScopes ?? []
  return async (c, next) => {
    try {
      const authHeader = c.req.header('authorization')
      if (!authHeader) throw new InvalidTokenError('Missing Authorization header')
      const [type, token] = authHeader.split(' ')
      if (type?.toLowerCase() !== 'bearer' || !token) {
        throw new InvalidTokenError("Invalid Authorization header format, expected 'Bearer TOKEN'")
      }
      const authInfo = await opts.verifier.verifyAccessToken(token)
      if (requiredScopes.length > 0) {
        const hasAll = requiredScopes.every((s) => authInfo.scopes.includes(s))
        if (!hasAll) throw new InsufficientScopeError('Insufficient scope')
      }
      if (typeof authInfo.expiresAt !== 'number' || isNaN(authInfo.expiresAt)) {
        throw new InvalidTokenError('Token has no expiration time')
      }
      if (authInfo.expiresAt < Date.now() / 1000) {
        throw new InvalidTokenError('Token has expired')
      }
      c.set('auth', authInfo)
      return next()
    } catch (err) {
      if (err instanceof InvalidTokenError) {
        return new Response(JSON.stringify(err.toResponseObject()), {
          status: 401,
          headers: {
            'content-type': 'application/json',
            'www-authenticate': buildWwwAuthHeader(
              err.errorCode,
              err.message,
              requiredScopes,
              opts.resourceMetadataUrl,
            ),
          },
        })
      }
      if (err instanceof InsufficientScopeError) {
        return new Response(JSON.stringify(err.toResponseObject()), {
          status: 403,
          headers: {
            'content-type': 'application/json',
            'www-authenticate': buildWwwAuthHeader(
              err.errorCode,
              err.message,
              requiredScopes,
              opts.resourceMetadataUrl,
            ),
          },
        })
      }
      return oauthErrorResponse(err, 400)
    }
  }
}
