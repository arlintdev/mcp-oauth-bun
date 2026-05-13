// OAuthServerProvider — the contract a consumer of this library
// implements to back the OAuth endpoints with storage + business
// logic. Ported from @modelcontextprotocol/sdk's provider.d.ts.
//
// The shape stays the same, but `authorize()` takes a Hono Context
// instead of an Express Response. That's the one place the API
// diverges from the SDK — the rest of the surface is byte-identical
// because the wire format is what matters.

import type { Context } from 'hono'
import type {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from './schemas'
import type { AuthInfo } from './types'

export type AuthorizationParams = {
  /** State param the client passed; echoed in the redirect. */
  state?: string
  /** Requested scopes. Provider validates against what it's willing to issue. */
  scopes?: string[]
  /** PKCE code_challenge, S256-encoded. */
  codeChallenge: string
  /** Client's redirect URI. Already validated against the registered list
   *  by the authorize handler before this method is called. */
  redirectUri: string
  /** RFC 8707 resource indicator. */
  resource?: URL
}

/** Store for registered OAuth clients (DCR + lookup). */
export interface OAuthRegisteredClientsStore {
  /** Look up a client by its client_id. */
  getClient(
    clientId: string,
  ): OAuthClientInformationFull | undefined | Promise<OAuthClientInformationFull | undefined>

  /** RFC 7591 Dynamic Client Registration. If omitted, DCR is disabled.
   *
   *  The router generates `client_id` + `client_secret` (for confidential
   *  clients) before calling this — the provider just persists what it
   *  gets and returns the same shape, plus any server-enforced overrides.
   *
   *  IMPORTANT: implementations MUST NOT delete expired secrets in-place.
   *  The router's client-auth middleware checks `client_secret_expires_at`
   *  on every token request and rejects expired ones. */
  registerClient?(
    client: OAuthClientInformationFull,
  ): OAuthClientInformationFull | Promise<OAuthClientInformationFull>
}

export interface OAuthServerProvider {
  /** The clients store. */
  get clientsStore(): OAuthRegisteredClientsStore

  /**
   * Begin the authorization flow. Provider is responsible for ensuring
   * the user is authenticated (typically via session cookie + UI consent
   * screen), and must eventually redirect back to `params.redirectUri`
   * with either `?code=...` (success) or `?error=...` (denial).
   *
   * On Hono we hand the Context — call `c.redirect(...)` to issue the
   * redirect. The router won't read anything from the context after
   * this returns; the response is yours to write.
   *
   * Errors thrown from this method are caught by the router and
   * surfaced to the client per RFC 6749 §4.1.2.1 (if redirect_uri is
   * known and trusted) or rendered as a 4xx (if not).
   */
  authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    c: Context,
  ): Promise<Response | void>

  /** Return the code_challenge stored for an authorization code at
   *  authorize time. The router does the PKCE S256 verification itself
   *  using this value. */
  challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string>

  /** Exchange an authorization code for tokens. */
  exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens>

  /** Exchange a refresh token for new tokens. Rotation is expected
   *  (the old refresh token is revoked, a new pair is issued). */
  exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens>

  /** Verify an access token. Used by the bearerAuth middleware for
   *  protected-resource routes. Throws InvalidTokenError on failure. */
  verifyAccessToken(token: string): Promise<AuthInfo>

  /** RFC 7009 revocation. Optional — if omitted, the router won't
   *  expose the revocation endpoint. */
  revokeToken?(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void>

  /** If true, the router skips local PKCE validation and passes
   *  code_verifier through to the provider — useful for AS proxies. */
  skipLocalPkceValidation?: boolean
}

/** Lightweight verifier-only interface for protected-resource servers
 *  that don't issue their own tokens (e.g. when the AS is a separate
 *  service). */
export interface OAuthTokenVerifier {
  verifyAccessToken(token: string): Promise<AuthInfo>
}
