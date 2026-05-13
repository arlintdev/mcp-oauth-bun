// Smoke tests for wire-shape equivalence with the SDK reference.
// These exercise the full mcpAuthRouter() against a tiny in-memory
// provider and assert on response shapes — same fields, same status
// codes, same content-type as @modelcontextprotocol/sdk.

import { test, expect, describe } from 'bun:test'
import { Hono } from 'hono'

// Hono's app.request() returns Response | Promise<Response>; in tests we
// always want to await as a Promise<Response>. Helper avoids `.then`
// type errors and gives a typed JSON body.
async function appReq(app: Hono, ...args: Parameters<Hono['request']>) {
  return (await app.request(...args)) as Response
}
async function appReqJson<T = any>(
  app: Hono,
  ...args: Parameters<Hono['request']>
): Promise<T> {
  return (await (await app.request(...args)).json()) as T
}
import {
  mcpAuthRouter,
  type OAuthServerProvider,
  type OAuthRegisteredClientsStore,
  type AuthorizationParams,
  type OAuthClientInformationFull,
  type OAuthTokens,
  type AuthInfo,
  InvalidGrantError,
} from '../src/index'

// ---- in-memory test provider ---------------------------------------

function makeProvider(): OAuthServerProvider & {
  _clients: Map<string, OAuthClientInformationFull>
  _codes: Map<string, { client_id: string; challenge: string }>
  _tokens: Map<string, AuthInfo>
} {
  const clients = new Map<string, OAuthClientInformationFull>()
  const codes = new Map<string, { client_id: string; challenge: string }>()
  const tokens = new Map<string, AuthInfo>()
  const store: OAuthRegisteredClientsStore = {
    getClient: (id) => clients.get(id),
    registerClient: (c) => {
      clients.set(c.client_id, c)
      return c
    },
  }
  return {
    _clients: clients,
    _codes: codes,
    _tokens: tokens,
    get clientsStore() {
      return store
    },
    async authorize(client, params: AuthorizationParams, c) {
      const code = `code-${Math.random().toString(36).slice(2)}`
      codes.set(code, { client_id: client.client_id, challenge: params.codeChallenge })
      const url = new URL(params.redirectUri)
      url.searchParams.set('code', code)
      if (params.state) url.searchParams.set('state', params.state)
      return c.redirect(url.toString())
    },
    async challengeForAuthorizationCode(_, code) {
      const entry = codes.get(code)
      if (!entry) throw new InvalidGrantError('Unknown code')
      return entry.challenge
    },
    async exchangeAuthorizationCode(client, code): Promise<OAuthTokens> {
      const entry = codes.get(code)
      if (!entry) throw new InvalidGrantError('Unknown code')
      codes.delete(code)
      const access = `tok-${Math.random().toString(36).slice(2)}`
      tokens.set(access, {
        token: access,
        clientId: client.client_id,
        scopes: [],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      })
      return {
        access_token: access,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'r-' + access,
      }
    },
    async exchangeRefreshToken(client): Promise<OAuthTokens> {
      const access = `tok-${Math.random().toString(36).slice(2)}`
      tokens.set(access, {
        token: access,
        clientId: client.client_id,
        scopes: [],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      })
      return {
        access_token: access,
        token_type: 'Bearer',
        expires_in: 3600,
      }
    },
    async verifyAccessToken(token): Promise<AuthInfo> {
      const info = tokens.get(token)
      if (!info) throw new Error('bad token')
      return info
    },
    async revokeToken(_, req) {
      tokens.delete(req.token)
    },
  }
}

function buildApp() {
  const provider = makeProvider()
  const app = new Hono()
  app.route(
    '/',
    mcpAuthRouter({
      provider,
      issuerUrl: new URL('https://example.test'),
      scopesSupported: ['read', 'write'],
    }),
  )
  return { app, provider }
}

// ---- tests ----------------------------------------------------------

// Regression: strict OAuth clients (e.g. Anthropic's MCP connector
// backend) compare the issuer they derived from the user-typed URL
// against what we publish, byte-for-byte. A trailing slash mismatch
// is fatal. Verify the canonical form strips the slash for bare hosts
// and preserves it for paths.
describe('issuer canonicalization (RFC 8414 §2)', () => {
  test('bare-host issuer has no trailing slash', async () => {
    const provider = makeProvider()
    const app = new Hono()
    app.route('/', mcpAuthRouter({ provider, issuerUrl: new URL('https://h.example') }))
    const md = await appReqJson<any>(app, '/.well-known/oauth-authorization-server')
    expect(md.issuer).toBe('https://h.example')
  })
  test('issuer with a non-root path preserves trailing slash semantics', async () => {
    const provider = makeProvider()
    const app = new Hono()
    app.route(
      '/',
      mcpAuthRouter({ provider, issuerUrl: new URL('https://h.example/tenant/') }),
    )
    const md = await appReqJson<any>(app, '/.well-known/oauth-authorization-server')
    expect(md.issuer).toBe('https://h.example/tenant/')
  })
})

describe('AS metadata', () => {
  test('returns RFC 8414 fields with correct content-type', async () => {
    const { app } = buildApp()
    const res = await app.request('/.well-known/oauth-authorization-server')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('application/json')
    expect(res.headers.get('access-control-allow-origin')).toBe('*')
    const body = (await res.json()) as any
    // RFC 8414 canonical issuer — no trailing slash for bare hosts.
    expect(body.issuer).toBe('https://example.test')
    expect(body.authorization_endpoint).toBe('https://example.test/authorize')
    expect(body.response_modes_supported).toEqual(['query'])
    expect(body.token_endpoint).toBe('https://example.test/token')
    expect(body.registration_endpoint).toBe('https://example.test/register')
    expect(body.revocation_endpoint).toBe('https://example.test/revoke')
    expect(body.response_types_supported).toEqual(['code'])
    expect(body.code_challenge_methods_supported).toEqual(['S256'])
    expect(body.token_endpoint_auth_methods_supported).toContain('client_secret_basic')
    expect(body.token_endpoint_auth_methods_supported).toContain('client_secret_post')
    expect(body.token_endpoint_auth_methods_supported).toContain('none')
    expect(body.scopes_supported).toEqual(['read', 'write'])
  })

  test('HEAD returns 200 with same headers, empty body', async () => {
    const { app } = buildApp()
    const res = await app.request('/.well-known/oauth-authorization-server', { method: 'HEAD' })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('application/json')
  })

  test('non-GET returns 405', async () => {
    const { app } = buildApp()
    const res = await app.request('/.well-known/oauth-authorization-server', { method: 'POST' })
    expect(res.status).toBe(405)
    expect(res.headers.get('allow')).toContain('GET')
  })
})

describe('PRM', () => {
  test('returns RFC 9728 fields', async () => {
    const { app } = buildApp()
    const res = await app.request('/.well-known/oauth-protected-resource')
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    // For bare-host resource (no /api/mcp path), the canonical form
    // strips the trailing slash.
    expect(body.resource).toBe('https://example.test')
    expect(body.authorization_servers).toEqual(['https://example.test'])
    expect(body.bearer_methods_supported).toEqual(['header'])
  })
})

describe('DCR /register', () => {
  test('issues client_id + client_secret for confidential clients', async () => {
    const { app } = buildApp()
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://client.test/cb'],
      }),
    })
    expect(res.status).toBe(201)
    const body = (await res.json()) as any
    expect(typeof body.client_id).toBe('string')
    expect(typeof body.client_secret).toBe('string')
    expect(body.redirect_uris).toEqual(['https://client.test/cb'])
    expect(typeof body.client_id_issued_at).toBe('number')
    expect(typeof body.client_secret_expires_at).toBe('number')
  })

  test('no secret issued for public clients', async () => {
    const { app } = buildApp()
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://client.test/cb'],
        token_endpoint_auth_method: 'none',
      }),
    })
    expect(res.status).toBe(201)
    const body = (await res.json()) as any
    expect(body.client_id).toBeDefined()
    expect(body.client_secret).toBeUndefined()
  })

  test('rejects invalid metadata', async () => {
    const { app } = buildApp()
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['javascript:alert(1)'] }),
    })
    expect(res.status).toBe(400)
    const body = (await res.json()) as any
    expect(body.error).toBe('invalid_client_metadata')
  })
})

// PKCE S256 helper for the next set of tests.
async function pkceS256(): Promise<{ verifier: string; challenge: string }> {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  const b64url = (b: Uint8Array) =>
    btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const verifier = b64url(bytes)
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)),
  )
  return { verifier, challenge: b64url(hash) }
}

describe('authorize → token (PKCE S256)', () => {
  test('happy path issues tokens', async () => {
    const { app } = buildApp()
    // 1) register a client
    const reg = await appReqJson<any>(app, '/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://client.test/cb'],
        token_endpoint_auth_method: 'none',
      }),
    })

    const { verifier, challenge } = await pkceS256()

    // 2) authorize
    const authUrl = new URL('https://example.test/authorize')
    authUrl.searchParams.set('client_id', reg.client_id)
    authUrl.searchParams.set('redirect_uri', 'https://client.test/cb')
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('code_challenge', challenge)
    authUrl.searchParams.set('code_challenge_method', 'S256')
    const authRes = await app.request(authUrl.pathname + authUrl.search)
    expect(authRes.status).toBe(302)
    const loc = new URL(authRes.headers.get('location')!)
    const code = loc.searchParams.get('code')!
    expect(code).toBeTruthy()

    // 3) token exchange (public client, no secret)
    const tokRes = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: reg.client_id,
        redirect_uri: 'https://client.test/cb',
      }).toString(),
    })
    expect(tokRes.status).toBe(200)
    expect(tokRes.headers.get('content-type')).toBe('application/json')
    expect(tokRes.headers.get('cache-control')).toBe('no-store')
    const tok = (await tokRes.json()) as any
    expect(typeof tok.access_token).toBe('string')
    expect(tok.token_type).toBe('Bearer')
    expect(tok.expires_in).toBe(3600)
  })

  test('rejects wrong PKCE verifier', async () => {
    const { app } = buildApp()
    const reg = await appReqJson<any>(app, '/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://client.test/cb'],
        token_endpoint_auth_method: 'none',
      }),
    })

    const { challenge } = await pkceS256()

    const authUrl = new URL('https://example.test/authorize')
    authUrl.searchParams.set('client_id', reg.client_id)
    authUrl.searchParams.set('redirect_uri', 'https://client.test/cb')
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('code_challenge', challenge)
    authUrl.searchParams.set('code_challenge_method', 'S256')
    const authRes = await app.request(authUrl.pathname + authUrl.search)
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!

    const tokRes = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: 'WRONG_VERIFIER',
        client_id: reg.client_id,
      }).toString(),
    })
    expect(tokRes.status).toBe(400)
    const body = (await tokRes.json()) as any
    expect(body.error).toBe('invalid_grant')
  })
})

describe('authorize: bad redirect_uri stays on AS origin', () => {
  test('unregistered redirect_uri returns 400 JSON, not a bounce', async () => {
    const { app } = buildApp()
    const reg = await appReqJson<any>(app, '/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://client.test/cb'] }),
    })
    const url = new URL('https://example.test/authorize')
    url.searchParams.set('client_id', reg.client_id)
    url.searchParams.set('redirect_uri', 'https://evil.test/cb')
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('code_challenge', 'x')
    const res = await app.request(url.pathname + url.search)
    expect(res.status).toBe(400)
    const body = (await res.json()) as any
    expect(body.error).toBe('invalid_request')
  })

  test('unsupported response_type bounces with error', async () => {
    const { app } = buildApp()
    const reg = await appReqJson<any>(app, '/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://client.test/cb'] }),
    })
    const url = new URL('https://example.test/authorize')
    url.searchParams.set('client_id', reg.client_id)
    url.searchParams.set('redirect_uri', 'https://client.test/cb')
    url.searchParams.set('response_type', 'token')
    url.searchParams.set('code_challenge', 'x')
    const res = await app.request(url.pathname + url.search)
    expect(res.status).toBe(302)
    const loc = new URL(res.headers.get('location')!)
    expect(loc.origin + loc.pathname).toBe('https://client.test/cb')
    expect(loc.searchParams.get('error')).toBe('unsupported_response_type')
  })
})
