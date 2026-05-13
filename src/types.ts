// Information about a validated access token. Returned by
// OAuthServerProvider.verifyAccessToken; attached to the Hono context
// by the bearerAuth middleware as `c.var.auth`.

export interface AuthInfo {
  /** The raw access token string. */
  token: string

  /** The client_id the token was issued to. */
  clientId: string

  /** Scopes granted to this token. */
  scopes: string[]

  /** Expiry as seconds since epoch. Optional — server-side stores
   *  expiry; the middleware just uses it to short-circuit a lookup
   *  after the provider has already validated it. */
  expiresAt?: number

  /** RFC 8707 audience binding. If set, the resource server middleware
   *  MUST compare against its canonical URI and reject mismatches. */
  resource?: URL

  /** Provider escape hatch — store anything else here (user_id, etc.).
   *  Pass-through; not used by the library. */
  extra?: Record<string, unknown>
}
