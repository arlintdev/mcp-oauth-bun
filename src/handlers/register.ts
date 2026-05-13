// RFC 7591 Dynamic Client Registration endpoint.
//
// Mirrors the SDK's clientRegistrationHandler:
//   - Accepts client metadata as JSON.
//   - Validates with OAuthClientMetadataSchema.
//   - Generates `client_id` (and `client_secret` for non-`none` token
//     auth methods).
//   - Stamps `client_id_issued_at` and optionally `client_secret_expires_at`.
//   - Calls provider.clientsStore.registerClient() to persist.
//   - Returns the full registration response (201).
//
// We use the platform `crypto` global (Bun + modern Node), so no
// node:crypto import — keeps the package portable across runtimes.

import type { MiddlewareHandler } from 'hono'
import {
  OAuthClientMetadataSchema,
  type OAuthClientInformationFull,
} from '../schemas'
import type { OAuthRegisteredClientsStore } from '../provider'
import {
  InvalidClientMetadataError,
  OAuthError,
  ServerError,
} from '../errors'

const DEFAULT_CLIENT_SECRET_EXPIRY_SECONDS = 30 * 24 * 60 * 60 // 30d

/** Random hex string from crypto.getRandomValues (no node:crypto). */
function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function clientRegistrationHandler(opts: {
  clientsStore: OAuthRegisteredClientsStore
  /** Lifetime of issued client secrets in seconds. Default 30d.
   *  Set to 0 to issue non-expiring secrets (per RFC 7591 §3.2.1
   *  client_secret_expires_at = 0 means "does not expire"). */
  clientSecretExpirySeconds?: number
  /** Override the default UUID for client_id (test hook). */
  clientIdGenerator?: () => string
  /** Override the default 32-byte hex for client_secret (test hook). */
  clientSecretGenerator?: () => string
}): MiddlewareHandler {
  const {
    clientsStore,
    clientSecretExpirySeconds = DEFAULT_CLIENT_SECRET_EXPIRY_SECONDS,
    clientIdGenerator = () => crypto.randomUUID(),
    clientSecretGenerator = () => randomHex(32),
  } = opts

  if (!clientsStore.registerClient) {
    throw new Error(
      'clientRegistrationHandler requires clientsStore.registerClient — ' +
        'the provider has not opted into Dynamic Client Registration.',
    )
  }

  return async (c) => {
    try {
      // Body is JSON per RFC 7591 §3.1.
      let raw: unknown
      try {
        raw = await c.req.json()
      } catch {
        throw new InvalidClientMetadataError(
          'Request body must be valid JSON',
        )
      }

      const parsed = OAuthClientMetadataSchema.safeParse(raw)
      if (!parsed.success) {
        throw new InvalidClientMetadataError(String(parsed.error))
      }
      const metadata = parsed.data

      // Determine if a secret is needed. RFC 7591 §2: if the client
      // sets token_endpoint_auth_method to 'none' (i.e. it's a public
      // client), don't issue a secret.
      const isPublic = metadata.token_endpoint_auth_method === 'none'

      const clientId = clientIdGenerator()
      const clientIdIssuedAt = Math.floor(Date.now() / 1000)

      const clientInfo: OAuthClientInformationFull = {
        ...metadata,
        client_id: clientId,
        client_id_issued_at: clientIdIssuedAt,
        ...(isPublic
          ? {}
          : {
              client_secret: clientSecretGenerator(),
              client_secret_expires_at:
                clientSecretExpirySeconds > 0
                  ? clientIdIssuedAt + clientSecretExpirySeconds
                  : 0,
            }),
      }

      const persisted = await clientsStore.registerClient!(clientInfo)
      return new Response(JSON.stringify(persisted), {
        status: 201,
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
