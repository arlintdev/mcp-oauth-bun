// The equivalent of @modelcontextprotocol/sdk's `mcpAuthRouter`:
// composes all the OAuth endpoints into a single Hono app you can
// mount on your main app via `app.route('/', oauthApp)`.
//
// What you get:
//   GET  /.well-known/oauth-authorization-server  → AS metadata (RFC 8414)
//   GET  /.well-known/oauth-protected-resource    → PRM (RFC 9728)
//   GET  /authorize                               → auth endpoint
//   POST /authorize                               → auth endpoint (some clients use POST)
//   POST /token                                   → token endpoint
//   POST /register                                → DCR (RFC 7591) if enabled
//   POST /revoke                                  → revocation (RFC 7009) if enabled
//
// All metadata documents are precomputed and served with permissive
// CORS. All endpoints emit content-type: application/json (no charset)
// to match the SDK exactly — strict OAuth clients string-compare this.

import { Hono } from 'hono'
import type { OAuthServerProvider } from './provider'
import type {
  OAuthMetadata,
  OAuthProtectedResourceMetadata,
} from './schemas'
import {
  allowedMethods,
  authenticateClient,
  type McpOauthVars,
} from './middleware'
import { metadataHandler } from './handlers/metadata'
import { clientRegistrationHandler } from './handlers/register'
import { authorizationHandler } from './handlers/authorize'
import { tokenHandler } from './handlers/token'
import { revocationHandler } from './handlers/revoke'

export interface McpAuthRouterOptions {
  /** Your OAuthServerProvider implementation. */
  provider: OAuthServerProvider

  /** Canonical `issuer` URL for this AS. Must be the public-facing
   *  origin (e.g. `https://pages.arlint.dev`), with no path. RFC 8414
   *  §2: this becomes the `issuer` field in AS metadata. */
  issuerUrl: URL

  /** Canonical resource URL (your protected resource). For MCP, this
   *  is typically the same origin as the issuer, optionally with a
   *  base path. Goes into PRM (`resource`) and is the expected RFC
   *  8707 audience. */
  resourceUrl?: URL

  /** Where to mount this router. Defaults to `''` (root). If your app
   *  serves OAuth under `/oauth`, set `baseUrl: new URL('/oauth', issuerUrl)`
   *  and metadata paths will be rewritten accordingly. */
  baseUrl?: URL

  /** Optional service-documentation URL for AS metadata. */
  serviceDocumentationUrl?: URL

  /** Scopes the AS advertises. */
  scopesSupported?: string[]

  /** Bearer methods the resource server advertises in PRM. */
  bearerMethodsSupported?: string[]

  /** Custom paths. Defaults mirror the SDK. */
  paths?: {
    authorization?: string // '/authorize'
    token?: string // '/token'
    registration?: string // '/register'
    revocation?: string // '/revoke'
  }
}

/** Build the URL the AS will advertise for an endpoint. Honors
 *  `baseUrl` so consumers can mount the router under a prefix. */
function endpointUrl(opts: McpAuthRouterOptions, path: string): URL {
  const base = opts.baseUrl ?? opts.issuerUrl
  return new URL(path.replace(/^\//, ''), base.toString().replace(/\/?$/, '/'))
}

/** Canonical issuer string. RFC 8414 §2 wants no trailing slash when
 *  the issuer URL has no path component — many validators (notably the
 *  Anthropic MCP connector backend) string-compare the issuer they
 *  derived from the user-supplied URL against the one we publish, and a
 *  bare `https://host/` vs `https://host` mismatch is fatal. We strip
 *  the trailing slash iff the path is just "/". */
function canonicalIssuer(url: URL): string {
  const href = url.href
  if (url.pathname === '/' && !url.search && !url.hash) {
    return href.replace(/\/$/, '')
  }
  return href
}

/** Build the AS metadata document. Field order matches the SDK so
 *  string-comparing clients see the same bytes. */
export function buildAuthorizationServerMetadata(
  opts: McpAuthRouterOptions,
): OAuthMetadata {
  const grantTypes = ['authorization_code', 'refresh_token']
  const hasRegistration = !!opts.provider.clientsStore.registerClient
  const hasRevocation = !!opts.provider.revokeToken

  const md: OAuthMetadata = {
    // RFC 8414 §2: issuer is the canonical URL of the AS. We strip the
    // trailing slash for bare-host issuers (path === "/") because the
    // Anthropic MCP connector backend (and other strict validators)
    // compare the issuer string-eq against the URL the user typed in;
    // they don't normalize trailing slashes. See canonicalIssuer().
    issuer: canonicalIssuer(opts.issuerUrl),
    authorization_endpoint: endpointUrl(
      opts,
      opts.paths?.authorization ?? '/authorize',
    ).href,
    token_endpoint: endpointUrl(opts, opts.paths?.token ?? '/token').href,
    response_types_supported: ['code'],
    // RFC 6749 §3.1.2 defines `query` as the default response_mode for
    // the code grant; including it explicitly mirrors what real
    // Anthropic-blessed MCP servers (e.g. Cloudflare's bindings.mcp)
    // emit, and some validators key off it.
    response_modes_supported: ['query'],
    grant_types_supported: grantTypes,
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: [
      'client_secret_post',
      'client_secret_basic',
      'none',
    ],
    scopes_supported: opts.scopesSupported,
    service_documentation: opts.serviceDocumentationUrl?.href,
  }
  if (hasRegistration) {
    md.registration_endpoint = endpointUrl(
      opts,
      opts.paths?.registration ?? '/register',
    ).href
  }
  if (hasRevocation) {
    md.revocation_endpoint = endpointUrl(
      opts,
      opts.paths?.revocation ?? '/revoke',
    ).href
    md.revocation_endpoint_auth_methods_supported = [
      'client_secret_post',
      'client_secret_basic',
    ]
  }
  return md
}

/** Build the protected-resource metadata (RFC 9728). */
export function buildProtectedResourceMetadata(
  opts: McpAuthRouterOptions,
): OAuthProtectedResourceMetadata {
  const resource = opts.resourceUrl ?? opts.issuerUrl
  return {
    // `resource` keeps any path component verbatim — for MCP it's the
    // /api/mcp endpoint, no normalization. authorization_servers must
    // match the AS's `issuer` byte-for-byte so we run it through the
    // same canonical form.
    resource: resource.href.replace(/\/$/, resource.pathname === '/' ? '' : '/'),
    authorization_servers: [canonicalIssuer(opts.issuerUrl)],
    scopes_supported: opts.scopesSupported,
    bearer_methods_supported: opts.bearerMethodsSupported ?? ['header'],
  }
}

/**
 * Compose all the OAuth endpoints into a Hono sub-app.
 *
 *     const oauth = mcpAuthRouter({ provider, issuerUrl: new URL(BASE) })
 *     app.route('/', oauth)
 */
export function mcpAuthRouter(
  opts: McpAuthRouterOptions,
): Hono<{ Variables: McpOauthVars }> {
  const app = new Hono<{ Variables: McpOauthVars }>()

  const asMetadata = buildAuthorizationServerMetadata(opts)
  const prMetadata = buildProtectedResourceMetadata(opts)

  // Discovery endpoints. Both well-known paths must respond on GET/HEAD.
  const asHandler = metadataHandler(asMetadata)
  const prHandler = metadataHandler(prMetadata)
  app.on(
    ['GET', 'HEAD'],
    '/.well-known/oauth-authorization-server',
    asHandler,
  )
  app.all('/.well-known/oauth-authorization-server', allowedMethods(['GET', 'HEAD']))
  app.on(
    ['GET', 'HEAD'],
    '/.well-known/oauth-protected-resource',
    prHandler,
  )
  app.all('/.well-known/oauth-protected-resource', allowedMethods(['GET', 'HEAD']))

  // Authorize (GET + POST per RFC 6749 §3.1).
  const authPath = opts.paths?.authorization ?? '/authorize'
  app.on(['GET', 'POST'], authPath, authorizationHandler({ provider: opts.provider }))
  app.all(authPath, allowedMethods(['GET', 'POST']))

  // Token (POST only, client-authenticated).
  const tokenPath = opts.paths?.token ?? '/token'
  app.post(
    tokenPath,
    authenticateClient({ clientsStore: opts.provider.clientsStore }),
    tokenHandler({ provider: opts.provider }),
  )
  app.all(tokenPath, allowedMethods(['POST']))

  // DCR if the provider opted in.
  if (opts.provider.clientsStore.registerClient) {
    const regPath = opts.paths?.registration ?? '/register'
    app.post(
      regPath,
      clientRegistrationHandler({ clientsStore: opts.provider.clientsStore }),
    )
    app.all(regPath, allowedMethods(['POST']))
  }

  // Revocation if the provider opted in.
  if (opts.provider.revokeToken) {
    const revPath = opts.paths?.revocation ?? '/revoke'
    app.post(
      revPath,
      authenticateClient({ clientsStore: opts.provider.clientsStore }),
      revocationHandler({ provider: opts.provider }),
    )
    app.all(revPath, allowedMethods(['POST']))
  }

  return app
}
