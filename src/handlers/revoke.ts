// RFC 7009 token revocation endpoint.
//
// Behavior, mirroring the SDK:
//   - 200 with empty JSON `{}` on success.
//   - Per RFC 7009 §2.2, "invalid tokens do not cause an error
//     response." We pass everything to the provider and treat its
//     thrown errors as either OAuth-shaped (4xx with body) or 500.
//   - Requires client auth (middleware already ran, so c.var.client
//     is set).

import type { MiddlewareHandler } from 'hono'
import type { OAuthServerProvider } from '../provider'
import { readFormOrJson, type McpOauthVars } from '../middleware'
import {
  OAuthTokenRevocationRequestSchema,
} from '../schemas'
import {
  InvalidRequestError,
  OAuthError,
  ServerError,
} from '../errors'

export function revocationHandler(opts: {
  provider: OAuthServerProvider
}): MiddlewareHandler<{ Variables: McpOauthVars }> {
  if (!opts.provider.revokeToken) {
    throw new Error(
      'revocationHandler requires provider.revokeToken — provider does not support revocation.',
    )
  }
  return async (c) => {
    try {
      const client = c.var.client
      if (!client) {
        throw new ServerError('client not authenticated (middleware missing?)')
      }
      const body = await readFormOrJson(c)
      const parsed = OAuthTokenRevocationRequestSchema.safeParse(body)
      if (!parsed.success) {
        throw new InvalidRequestError(String(parsed.error))
      }
      await opts.provider.revokeToken!(client, parsed.data)
      return new Response('{}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
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
