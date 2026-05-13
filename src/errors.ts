// OAuth 2.1 / MCP error taxonomy.
//
// Ported byte-for-byte from @modelcontextprotocol/sdk's errors.js so that
// every error code, every wire shape, and every status-code mapping
// matches the SDK reference. Strict OAuth clients (including Anthropic's
// MCP connector backend) test against exact error codes, so we keep the
// same names and the same RFC mapping.

/** Standard OAuth 2.0 error response shape (RFC 6749 §5.2). */
export type OAuthErrorResponse = {
  error: string
  error_description: string
  error_uri?: string
}

/** Base class. Subclasses set `errorCode` on the constructor itself
 *  (the static value), and at instance time we resolve to that via the
 *  `errorCode` getter. Mirrors the SDK pattern. */
export abstract class OAuthError extends Error {
  static errorCode: string
  constructor(
    message: string,
    public errorUri?: string,
  ) {
    super(message)
    this.name = this.constructor.name
  }
  get errorCode(): string {
    return (this.constructor as typeof OAuthError).errorCode
  }
  toResponseObject(): OAuthErrorResponse {
    const out: OAuthErrorResponse = {
      error: this.errorCode,
      error_description: this.message,
    }
    if (this.errorUri) out.error_uri = this.errorUri
    return out
  }
}

/** RFC 6749 §5.2 */
export class InvalidRequestError extends OAuthError {
  static override errorCode = 'invalid_request'
}
/** RFC 6749 §5.2 — client auth failed (unknown client, missing/bad
 *  client_secret, unsupported auth method). */
export class InvalidClientError extends OAuthError {
  static override errorCode = 'invalid_client'
}
/** RFC 6749 §5.2 — grant (auth code or refresh token) invalid/expired/
 *  revoked / mismatched redirect_uri / issued to a different client. */
export class InvalidGrantError extends OAuthError {
  static override errorCode = 'invalid_grant'
}
export class UnauthorizedClientError extends OAuthError {
  static override errorCode = 'unauthorized_client'
}
export class UnsupportedGrantTypeError extends OAuthError {
  static override errorCode = 'unsupported_grant_type'
}
export class InvalidScopeError extends OAuthError {
  static override errorCode = 'invalid_scope'
}
export class AccessDeniedError extends OAuthError {
  static override errorCode = 'access_denied'
}
export class ServerError extends OAuthError {
  static override errorCode = 'server_error'
}
export class TemporarilyUnavailableError extends OAuthError {
  static override errorCode = 'temporarily_unavailable'
}
export class UnsupportedResponseTypeError extends OAuthError {
  static override errorCode = 'unsupported_response_type'
}
export class UnsupportedTokenTypeError extends OAuthError {
  static override errorCode = 'unsupported_token_type'
}
/** RFC 6750 §3.1 — bearer token failed validation. */
export class InvalidTokenError extends OAuthError {
  static override errorCode = 'invalid_token'
}
/** Custom — HTTP method gate failure. Not in RFC, surfaced by the SDK. */
export class MethodNotAllowedError extends OAuthError {
  static override errorCode = 'method_not_allowed'
}
/** RFC 6585 — rate limit exceeded. */
export class TooManyRequestsError extends OAuthError {
  static override errorCode = 'too_many_requests'
}
/** RFC 7591 — DCR client metadata bad. */
export class InvalidClientMetadataError extends OAuthError {
  static override errorCode = 'invalid_client_metadata'
}
/** RFC 6750 §3.1 — scope insufficient. */
export class InsufficientScopeError extends OAuthError {
  static override errorCode = 'insufficient_scope'
}
/** RFC 8707 — resource indicator rejected. */
export class InvalidTargetError extends OAuthError {
  static override errorCode = 'invalid_target'
}

/** Escape hatch for one-off errors not listed above. */
export class CustomOAuthError extends OAuthError {
  static override errorCode = 'unknown_error'
  constructor(
    private readonly customErrorCode: string,
    message: string,
    errorUri?: string,
  ) {
    super(message, errorUri)
  }
  override get errorCode(): string {
    return this.customErrorCode
  }
}

/** Lookup table for parsing error responses back into typed errors. */
export const OAUTH_ERRORS: Record<string, typeof OAuthError> = {
  [InvalidRequestError.errorCode]: InvalidRequestError as unknown as typeof OAuthError,
  [InvalidClientError.errorCode]: InvalidClientError as unknown as typeof OAuthError,
  [InvalidGrantError.errorCode]: InvalidGrantError as unknown as typeof OAuthError,
  [UnauthorizedClientError.errorCode]: UnauthorizedClientError as unknown as typeof OAuthError,
  [UnsupportedGrantTypeError.errorCode]: UnsupportedGrantTypeError as unknown as typeof OAuthError,
  [InvalidScopeError.errorCode]: InvalidScopeError as unknown as typeof OAuthError,
  [AccessDeniedError.errorCode]: AccessDeniedError as unknown as typeof OAuthError,
  [ServerError.errorCode]: ServerError as unknown as typeof OAuthError,
  [TemporarilyUnavailableError.errorCode]: TemporarilyUnavailableError as unknown as typeof OAuthError,
  [UnsupportedResponseTypeError.errorCode]: UnsupportedResponseTypeError as unknown as typeof OAuthError,
  [UnsupportedTokenTypeError.errorCode]: UnsupportedTokenTypeError as unknown as typeof OAuthError,
  [InvalidTokenError.errorCode]: InvalidTokenError as unknown as typeof OAuthError,
  [MethodNotAllowedError.errorCode]: MethodNotAllowedError as unknown as typeof OAuthError,
  [TooManyRequestsError.errorCode]: TooManyRequestsError as unknown as typeof OAuthError,
  [InvalidClientMetadataError.errorCode]: InvalidClientMetadataError as unknown as typeof OAuthError,
  [InsufficientScopeError.errorCode]: InsufficientScopeError as unknown as typeof OAuthError,
  [InvalidTargetError.errorCode]: InvalidTargetError as unknown as typeof OAuthError,
}
