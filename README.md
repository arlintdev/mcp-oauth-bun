# @arlintdev/mcp-oauth-bun

Hono-native port of [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk)'s OAuth 2.1 authorization server. Drop-in for Bun + Hono MCP servers, byte-for-byte wire-compatible with the SDK's reference router — so strict OAuth clients (including Claude's MCP connector backend) accept it without the `mcp-remote` shim.

> **Why this exists.** The SDK ships an OAuth router, but only as Express middleware. If you're on Bun + Hono, you'd otherwise have to bridge Fetch ↔ node-http to use it (and Bun's `ServerResponse` compat doesn't quite get you there). This package ports the same logic over to native Hono handlers, preserving every status code, header, and JSON body the SDK emits.

## Install

```sh
bun add @arlintdev/mcp-oauth-bun hono zod
```

## Quick start

```ts
import { Hono } from 'hono'
import {
  mcpAuthRouter,
  requireBearerAuth,
  type OAuthServerProvider,
} from '@arlintdev/mcp-oauth-bun'

// Implement the provider against your storage (SQLite, Postgres, …).
const provider: OAuthServerProvider = {
  get clientsStore() { return /* … */ },
  async authorize(client, params, c) { /* render consent, then c.redirect(...) */ },
  async challengeForAuthorizationCode(client, code) { /* return stored code_challenge */ },
  async exchangeAuthorizationCode(client, code) { /* issue tokens */ },
  async exchangeRefreshToken(client, refreshToken) { /* rotate */ },
  async verifyAccessToken(token) { /* return AuthInfo */ },
  async revokeToken(client, request) { /* optional */ },
}

const app = new Hono()

// Mount the OAuth endpoints (.well-known, /authorize, /token, /register, /revoke).
app.route('/', mcpAuthRouter({
  provider,
  issuerUrl: new URL('https://example.com'),
  scopesSupported: ['read', 'write'],
}))

// Protect your MCP endpoint with the bearer middleware.
app.post(
  '/mcp',
  requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: 'https://example.com/.well-known/oauth-protected-resource',
  }),
  async (c) => {
    const auth = c.var.auth // AuthInfo
    // …MCP request handling…
  },
)

export default app
```

## What you get

Mounting `mcpAuthRouter()` adds the full OAuth 2.1 + MCP profile surface:

| Endpoint | Spec | Notes |
| --- | --- | --- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | AS metadata document |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | PRM for MCP discovery from 401s |
| `GET\|POST /authorize` | RFC 6749 §4.1 + PKCE S256 | MCP profile requires PKCE |
| `POST /token` | RFC 6749 §3.2 | `authorization_code` + `refresh_token` |
| `POST /register` | RFC 7591 | DCR — only mounted if your provider implements `registerClient` |
| `POST /revoke` | RFC 7009 | Only mounted if your provider implements `revokeToken` |

The `requireBearerAuth` middleware adds RFC 9728 §5.1 compliance: 401s emit a `WWW-Authenticate: Bearer ..., resource_metadata="..."` header so MCP clients can auto-discover the AS.

## Compatibility notes

- **Wire-shape identical to the SDK.** Same `content-type: application/json` (no charset), same field order in metadata docs, same error codes. Tested against strict validators.
- **Basic auth on `/token` and `/revoke`.** Per RFC 6749 §2.3.1, Basic is the preferred client auth method for confidential clients. The SDK's stock middleware only reads from the body — we accept both.
- **POST `/authorize`.** RFC 6749 §3.1 allows POST. Some MCP clients prefer it.
- **PKCE S256 only.** We don't accept `plain` per the MCP spec.
- **Loopback redirect ports** are matched per RFC 8252 §7.3 (port ignored for `127.0.0.1`/`[::1]`).

## API stability

`0.x` — wire shape and provider interfaces are stable; minor cleanups may still touch internal helpers. Track the changelog.

## License

MIT
