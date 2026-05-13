// Public API surface for @arlintdev/mcp-oauth-bun.
//
// Everything a consumer needs to wire MCP-spec OAuth 2.1 into a
// Hono + Bun app: the router, the middleware (for resource-server
// endpoints), the provider interfaces they implement, the Zod
// schemas, and the full error taxonomy.

// --- Router (the main entrypoint) ------------------------------------
export {
  mcpAuthRouter,
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  type McpAuthRouterOptions,
} from './router'

// --- Individual handlers ---------------------------------------------
// Most consumers will mount `mcpAuthRouter`, but some need to compose
// handlers manually (e.g. to swap in a custom client-auth middleware).
export { authorizationHandler } from './handlers/authorize'
export { tokenHandler } from './handlers/token'
export { revocationHandler } from './handlers/revoke'
export { clientRegistrationHandler } from './handlers/register'
export { metadataHandler } from './handlers/metadata'

// --- Middleware (mount on protected-resource routes) -----------------
export {
  requireBearerAuth,
  authenticateClient,
  allowedMethods,
  readFormOrJson,
  type McpOauthVars,
} from './middleware'

// --- Provider contracts (consumers implement these) ------------------
export type {
  OAuthServerProvider,
  OAuthRegisteredClientsStore,
  OAuthTokenVerifier,
  AuthorizationParams,
} from './provider'

export type { AuthInfo } from './types'

// --- Schemas + inferred types ---------------------------------------
export {
  SafeUrlSchema,
  OAuthProtectedResourceMetadataSchema,
  OAuthMetadataSchema,
  OAuthTokensSchema,
  OAuthErrorResponseSchema,
  OAuthClientMetadataSchema,
  OAuthClientInformationSchema,
  OAuthClientInformationFullSchema,
  OAuthTokenRevocationRequestSchema,
  type OAuthMetadata,
  type OAuthProtectedResourceMetadata,
  type OAuthTokens,
  type OAuthClientMetadata,
  type OAuthClientInformationFull,
  type OAuthTokenRevocationRequest,
} from './schemas'

// --- Error taxonomy --------------------------------------------------
export {
  OAuthError,
  InvalidRequestError,
  InvalidClientError,
  InvalidGrantError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  InvalidScopeError,
  AccessDeniedError,
  ServerError,
  TemporarilyUnavailableError,
  UnsupportedResponseTypeError,
  UnsupportedTokenTypeError,
  InvalidTokenError,
  MethodNotAllowedError,
  TooManyRequestsError,
  InvalidClientMetadataError,
  InsufficientScopeError,
  InvalidTargetError,
  CustomOAuthError,
  OAUTH_ERRORS,
  type OAuthErrorResponse,
} from './errors'
