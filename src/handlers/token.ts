// RFC 6749 §3.2 token endpoint. Handles two grant types:
//   - authorization_code (with mandatory PKCE S256 verification)
//   - refresh_token
//
// PKCE verification is done locally by SHA-256-hashing the verifier
// and base64url-encoding it, then comparing to the challenge the
// provider stored at authorize time. The SDK does this same dance
// using `pkce-challenge`; we inline it to keep the dep tree clean.
//
// We assume the `authenticateClient` middleware ran first, so
// `c.var.client` is set.

import type { MiddlewareHandler } from 'hono'
import { z } from 'zod'
import type { OAuthServerProvider } from '../provider'
import { readFormOrJson, type McpOauthVars } from '../middleware'
import {
  InvalidGrantError,
  InvalidRequestError,
  OAuthError,
  ServerError,
  UnsupportedGrantTypeError,
} from '../errors'

/** base64url-encode a byte array (no padding, URL-safe). */
function b64url(bytes: Uint8Array): string {
  // btoa requires a binary string. Build it without forming a giant
  // string for very large inputs (32 bytes here, so fine either way).
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** PKCE S256 verify: sha256(verifier) base64url-encoded == challenge. */
async function verifyPkceS256(verifier: string, challenge: string): Promise<boolean> {
  const data = new TextEncoder().encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return b64url(new Uint8Array(hash)) === challenge
}

// Schemas, mirroring the SDK's exactly.
const AuthCodeGrantSchema = z.object({
  code: z.string(),
  code_verifier: z.string(),
  redirect_uri: z.string().optional(),
  resource: z.string().url().optional(),
})

const RefreshGrantSchema = z.object({
  refresh_token: z.string(),
  scope: z.string().optional(),
  resource: z.string().url().optional(),
})

export function tokenHandler(opts: {
  provider: OAuthServerProvider
}): MiddlewareHandler<{ Variables: McpOauthVars }> {
  return async (c) => {
    try {
      const client = c.var.client
      if (!client) {
        // The client-auth middleware should have set this; defensive.
        throw new ServerError('client not authenticated (middleware missing?)')
      }
      const body = await readFormOrJson(c)
      const grantType = body.grant_type

      // Spec-compliant cache-control headers per RFC 6749 §5.1.
      const tokenHeaders: Record<string, string> = {
        'content-type': 'application/json',
        'cache-control': 'no-store',
        pragma: 'no-cache',
      }

      if (grantType === 'authorization_code') {
        const parsed = AuthCodeGrantSchema.safeParse(body)
        if (!parsed.success) {
          throw new InvalidRequestError(String(parsed.error))
        }
        const { code, code_verifier, redirect_uri, resource } = parsed.data

        // Resource is RFC 8707 — parse to URL if present.
        let resourceUrl: URL | undefined
        if (resource) {
          try {
            resourceUrl = new URL(resource)
          } catch {
            throw new InvalidRequestError('resource must be a valid URI')
          }
        }

        // PKCE: if the provider proxies PKCE (e.g. forwards to an
        // upstream AS), it can opt out of local validation.
        if (!opts.provider.skipLocalPkceValidation) {
          const expected = await opts.provider.challengeForAuthorizationCode(
            client,
            code,
          )
          const ok = await verifyPkceS256(code_verifier, expected)
          if (!ok) throw new InvalidGrantError('Invalid code_verifier')
        }

        const tokens = await opts.provider.exchangeAuthorizationCode(
          client,
          code,
          // Pass code_verifier through iff the provider opted to
          // validate PKCE itself (otherwise we already did).
          opts.provider.skipLocalPkceValidation ? code_verifier : undefined,
          redirect_uri,
          resourceUrl,
        )

        return new Response(JSON.stringify(tokens), {
          status: 200,
          headers: tokenHeaders,
        })
      }

      if (grantType === 'refresh_token') {
        const parsed = RefreshGrantSchema.safeParse(body)
        if (!parsed.success) {
          throw new InvalidRequestError(String(parsed.error))
        }
        const { refresh_token, scope, resource } = parsed.data
        const scopes = scope ? scope.split(/\s+/).filter(Boolean) : undefined

        let resourceUrl: URL | undefined
        if (resource) {
          try {
            resourceUrl = new URL(resource)
          } catch {
            throw new InvalidRequestError('resource must be a valid URI')
          }
        }

        const tokens = await opts.provider.exchangeRefreshToken(
          client,
          refresh_token,
          scopes,
          resourceUrl,
        )
        return new Response(JSON.stringify(tokens), {
          status: 200,
          headers: tokenHeaders,
        })
      }

      throw new UnsupportedGrantTypeError(
        `Unsupported grant_type: ${String(grantType)}`,
      )
    } catch (err) {
      if (err instanceof OAuthError) {
        const status = err instanceof ServerError ? 500 : 400
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
  }
}
