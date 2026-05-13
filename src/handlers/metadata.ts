// AS metadata (RFC 8414) + protected-resource metadata (RFC 9728)
// endpoints. The SDK's metadataHandler just JSON-stringifies the
// provided document and serves it with a permissive CORS header.
// We do the same, plus a HEAD handler (some discovery clients HEAD
// before they GET) and 405 gating to match the SDK exactly.

import type { Context, MiddlewareHandler } from 'hono'
import type {
  OAuthMetadata,
  OAuthProtectedResourceMetadata,
} from '../schemas'
import { allowedMethods } from '../middleware'

/** Build a GET/HEAD handler for a metadata document. */
export function metadataHandler(
  metadata: OAuthMetadata | OAuthProtectedResourceMetadata,
): MiddlewareHandler {
  // Pre-serialize once. The SDK does this lazily on every call; we
  // hoist it because Hono handlers can be hot.
  const body = JSON.stringify(metadata, null, 2)
  return async (c: Context) => {
    if (c.req.method === 'HEAD') {
      return new Response(null, {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': '*',
        },
      })
    }
    return new Response(body, {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'access-control-allow-origin': '*',
      },
    })
  }
}

/** Wrapper that gates non-GET/HEAD with a 405, mirroring the SDK. */
export const metadataAllowedMethods = (): MiddlewareHandler =>
  allowedMethods(['GET', 'HEAD'])
