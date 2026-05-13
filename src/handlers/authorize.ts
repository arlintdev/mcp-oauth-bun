// RFC 6749 §4.1 authorization endpoint, plus the MCP profile bits
// from spec 2025-06-18 (PKCE required, resource indicator).
//
// Two-phase error handling, mirroring the SDK exactly:
//
//   PRE-redirect errors (before we've validated the redirect_uri):
//     - Unknown client_id → 400 JSON
//     - Bad/missing redirect_uri → 400 JSON
//     The user MUST see this on our domain; we never bounce back to
//     a URL we can't trust.
//
//   POST-redirect errors (after redirect_uri is known-good):
//     - Per RFC 6749 §4.1.2.1, return 302 to redirect_uri with
//       ?error=... so the client sees the failure.
//
// PKCE is REQUIRED (we don't accept code_challenge_method=plain).

import type { MiddlewareHandler } from 'hono'
import { z } from 'zod'
import type { OAuthServerProvider } from '../provider'
import {
  InvalidClientError,
  InvalidRequestError,
  InvalidScopeError,
  ServerError,
  UnsupportedResponseTypeError,
  OAuthError,
} from '../errors'

/**
 * RFC 6749 §3.1.2.2 redirect_uri matching. Default behavior: byte-for-byte
 * equality against the registered set. The SDK accepts an optional
 * loopback-port relaxation (RFC 8252 §7.3) for native clients —
 * `http://127.0.0.1:<port>/...` matches a registered `http://127.0.0.1/...`
 * regardless of port. We replicate that.
 */
function redirectUriMatches(
  requested: string,
  registered: string[],
): boolean {
  if (registered.includes(requested)) return true
  // RFC 8252 §7.3 loopback relaxation.
  let req: URL
  try {
    req = new URL(requested)
  } catch {
    return false
  }
  if (req.hostname !== '127.0.0.1' && req.hostname !== '[::1]') return false
  for (const r of registered) {
    let reg: URL
    try {
      reg = new URL(r)
    } catch {
      continue
    }
    if (
      reg.protocol === req.protocol &&
      reg.hostname === req.hostname &&
      reg.pathname === req.pathname &&
      reg.search === req.search
    ) {
      return true
    }
  }
  return false
}

// Query/form schema (RFC 6749 §4.1.1 + PKCE + RFC 8707 resource).
const AuthorizeRequestSchema = z.object({
  client_id: z.string(),
  response_type: z.string().default('code'),
  redirect_uri: z.string().optional(),
  code_challenge: z.string(),
  code_challenge_method: z.string().default('S256'),
  scope: z.string().optional(),
  state: z.string().optional(),
  resource: z.string().optional(),
})

export function authorizationHandler(opts: {
  provider: OAuthServerProvider
}): MiddlewareHandler {
  return async (c) => {
    // RFC 6749 §3.1: support both GET (query) and POST (form). The
    // SDK only registers GET; we accept POST too because some MCP
    // clients prefer it.
    let raw: Record<string, string> = {}
    if (c.req.method === 'POST') {
      const ct = (c.req.header('content-type') || '').toLowerCase()
      if (ct.includes('application/x-www-form-urlencoded')) {
        const text = await c.req.text()
        const params = new URLSearchParams(text)
        params.forEach((v, k) => {
          raw[k] = v
        })
      } else if (ct.includes('application/json')) {
        try {
          raw = (await c.req.json()) as Record<string, string>
        } catch {
          raw = {}
        }
      }
    } else {
      const url = new URL(c.req.url)
      url.searchParams.forEach((v, k) => {
        raw[k] = v
      })
    }

    // ---- Phase 1: pre-redirect validation. ---------------------------
    // We MUST resolve a trusted redirect_uri before bouncing errors
    // back to the client. If anything in this block fails, render
    // a 400 on OUR origin — never trust the caller's URL yet.

    let client
    let redirect_uri: string
    try {
      const client_id = raw.client_id
      if (!client_id || typeof client_id !== 'string') {
        throw new InvalidRequestError('client_id is required')
      }
      client = await opts.provider.clientsStore.getClient(client_id)
      if (!client) throw new InvalidClientError('Invalid client_id')

      // Pick redirect_uri: if the request supplied one, validate against
      // the registered set; if it didn't, fall back to the sole
      // registered URI iff there's exactly one.
      const requested = raw.redirect_uri
      if (requested) {
        if (!redirectUriMatches(requested, client.redirect_uris)) {
          throw new InvalidRequestError('Unregistered redirect_uri')
        }
        redirect_uri = requested
      } else if (client.redirect_uris.length === 1) {
        redirect_uri = client.redirect_uris[0]!
      } else {
        throw new InvalidRequestError(
          'redirect_uri must be specified when multiple are registered',
        )
      }
    } catch (err) {
      if (err instanceof OAuthError) {
        return new Response(JSON.stringify(err.toResponseObject()), {
          status: err instanceof ServerError ? 500 : 400,
          headers: { 'content-type': 'application/json' },
        })
      }
      const se = new ServerError('Internal Server Error')
      return new Response(JSON.stringify(se.toResponseObject()), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      })
    }

    // ---- Phase 2: post-redirect validation. -------------------------
    // From here on, errors bounce back to redirect_uri per §4.1.2.1.
    const state = typeof raw.state === 'string' ? raw.state : undefined
    const bounceError = (err: OAuthError): Response => {
      const url = new URL(redirect_uri)
      url.searchParams.set('error', err.errorCode)
      url.searchParams.set('error_description', err.message)
      if (state) url.searchParams.set('state', state)
      return new Response(null, {
        status: 302,
        headers: { location: url.toString() },
      })
    }

    try {
      const parsed = AuthorizeRequestSchema.safeParse(raw)
      if (!parsed.success) {
        // Find the first issue with a useful path for the description.
        const msg = parsed.error.issues
          .map((i) => `${i.path.join('.')}: ${i.message}`)
          .join('; ')
        throw new InvalidRequestError(msg || 'Invalid request')
      }
      const p = parsed.data

      if (p.response_type !== 'code') {
        throw new UnsupportedResponseTypeError(
          `Unsupported response_type: ${p.response_type}`,
        )
      }
      if (p.code_challenge_method !== 'S256') {
        throw new InvalidRequestError(
          `code_challenge_method must be S256, got ${p.code_challenge_method}`,
        )
      }

      // Scope check: caller-requested vs. registered subset.
      const requestedScopes = p.scope ? p.scope.split(/\s+/).filter(Boolean) : undefined
      if (requestedScopes && client.scope) {
        const allowed = new Set(client.scope.split(/\s+/).filter(Boolean))
        for (const s of requestedScopes) {
          if (!allowed.has(s)) {
            throw new InvalidScopeError(`Client was not registered with scope: ${s}`)
          }
        }
      }

      // RFC 8707 resource indicator — parse to URL if present.
      let resource: URL | undefined
      if (p.resource) {
        try {
          resource = new URL(p.resource)
        } catch {
          throw new InvalidRequestError('resource must be a valid URI')
        }
      }

      // Hand off to the provider. The provider issues a redirect
      // (success: ?code=... ; denial: ?error=access_denied) on its own.
      const response = await opts.provider.authorize(
        client,
        {
          state,
          scopes: requestedScopes,
          codeChallenge: p.code_challenge,
          redirectUri: redirect_uri,
          resource,
        },
        c,
      )
      // If the provider returned a Response (Hono c.redirect or a
      // rendered consent page), pass it through. If it returned void
      // (already wrote to c via c.res), Hono will handle it.
      if (response instanceof Response) return response
      return c.res
    } catch (err) {
      if (err instanceof OAuthError) return bounceError(err)
      // Unknown errors: 500-ish but still bounced (the SDK does this).
      return bounceError(new ServerError('Internal Server Error'))
    }
  }
}
