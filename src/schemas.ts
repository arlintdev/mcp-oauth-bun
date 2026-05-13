// OAuth 2.1 / MCP wire-shape schemas.
//
// Ported from @modelcontextprotocol/sdk's shared/auth.js. Kept Zod 4
// idioms (`z.url()`, `z.looseObject()`, etc.) so the validation
// semantics match exactly. We trim OIDC-specific stuff that's not in
// the MCP spec.
//
// Field order in these objects matters for wire format equivalence —
// some clients string-compare metadata responses. We mirror the SDK
// order.

import { z } from 'zod'

/**
 * URL that disallows javascript:, data:, vbscript: schemes — the
 * usual short-circuit-XSS guard. Mirrors the SDK's SafeUrlSchema.
 */
export const SafeUrlSchema = z
  .url()
  .superRefine((val, ctx) => {
    if (!URL.canParse(val)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'URL must be parseable',
        fatal: true,
      })
      return z.NEVER
    }
  })
  .refine(
    (url) => {
      const u = new URL(url)
      return u.protocol !== 'javascript:' && u.protocol !== 'data:' && u.protocol !== 'vbscript:'
    },
    { message: 'URL cannot use javascript:, data:, or vbscript: scheme' },
  )

/** RFC 9728 OAuth Protected Resource Metadata. */
export const OAuthProtectedResourceMetadataSchema = z.looseObject({
  resource: z.url(),
  authorization_servers: z.array(SafeUrlSchema).optional(),
  jwks_uri: z.url().optional(),
  scopes_supported: z.array(z.string()).optional(),
  bearer_methods_supported: z.array(z.string()).optional(),
  resource_signing_alg_values_supported: z.array(z.string()).optional(),
  resource_name: z.string().optional(),
  resource_documentation: z.string().optional(),
  resource_policy_uri: z.url().optional(),
  resource_tos_uri: z.url().optional(),
})

/** RFC 8414 OAuth 2.0 Authorization Server Metadata. */
export const OAuthMetadataSchema = z.looseObject({
  issuer: z.string(),
  authorization_endpoint: SafeUrlSchema,
  token_endpoint: SafeUrlSchema,
  registration_endpoint: SafeUrlSchema.optional(),
  scopes_supported: z.array(z.string()).optional(),
  response_types_supported: z.array(z.string()),
  response_modes_supported: z.array(z.string()).optional(),
  grant_types_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  token_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
  service_documentation: SafeUrlSchema.optional(),
  revocation_endpoint: SafeUrlSchema.optional(),
  revocation_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  introspection_endpoint: z.string().optional(),
  introspection_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  client_id_metadata_document_supported: z.boolean().optional(),
})

export type OAuthMetadata = z.infer<typeof OAuthMetadataSchema>
export type OAuthProtectedResourceMetadata = z.infer<typeof OAuthProtectedResourceMetadataSchema>

/** RFC 6749 §5.1 token endpoint response. */
export const OAuthTokensSchema = z
  .object({
    access_token: z.string(),
    id_token: z.string().optional(),
    token_type: z.string(),
    expires_in: z.coerce.number().optional(),
    scope: z.string().optional(),
    refresh_token: z.string().optional(),
  })
  .strip()
export type OAuthTokens = z.infer<typeof OAuthTokensSchema>

/** RFC 6749 §5.2 error response. */
export const OAuthErrorResponseSchema = z
  .object({
    error: z.string(),
    error_description: z.string().optional(),
    error_uri: z.string().optional(),
  })
  .strip()

/** Optional URL field that also accepts empty string (back-compat). */
const OptionalSafeUrlSchema = SafeUrlSchema.optional().or(
  z.literal('').transform(() => undefined),
)

/** RFC 7591 DCR client metadata. Input to the registration endpoint. */
export const OAuthClientMetadataSchema = z
  .object({
    redirect_uris: z.array(SafeUrlSchema),
    token_endpoint_auth_method: z.string().optional(),
    grant_types: z.array(z.string()).optional(),
    response_types: z.array(z.string()).optional(),
    client_name: z.string().optional(),
    client_uri: SafeUrlSchema.optional(),
    logo_uri: OptionalSafeUrlSchema,
    scope: z.string().optional(),
    contacts: z.array(z.string()).optional(),
    tos_uri: OptionalSafeUrlSchema,
    policy_uri: z.string().optional(),
    jwks_uri: SafeUrlSchema.optional(),
    jwks: z.any().optional(),
    software_id: z.string().optional(),
    software_version: z.string().optional(),
    software_statement: z.string().optional(),
  })
  .strip()
export type OAuthClientMetadata = z.infer<typeof OAuthClientMetadataSchema>

/** RFC 7591 client information (server-assigned fields). */
export const OAuthClientInformationSchema = z
  .object({
    client_id: z.string(),
    client_secret: z.string().optional(),
    client_id_issued_at: z.number().optional(),
    client_secret_expires_at: z.number().optional(),
  })
  .strip()

/** Full registration response: metadata + server-assigned IDs. */
export const OAuthClientInformationFullSchema = z
  .object({
    ...OAuthClientMetadataSchema.shape,
    ...OAuthClientInformationSchema.shape,
  })
  .strip()
export type OAuthClientInformationFull = z.infer<typeof OAuthClientInformationFullSchema>

/** RFC 7009 revocation request body. */
export const OAuthTokenRevocationRequestSchema = z
  .object({
    token: z.string(),
    token_type_hint: z.string().optional(),
  })
  .strip()
export type OAuthTokenRevocationRequest = z.infer<typeof OAuthTokenRevocationRequestSchema>
