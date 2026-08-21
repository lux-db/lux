---
name: auth-flow-security
description: Use when implementing or debugging Lux signup, login, sessions, OAuth, SSR cookies, project-key boundaries, providers, or row-level grants.
---

# Lux App Auth Integration

Start with the requested flow's minimal runnable path. Before emitting code, verify the exact `@luxdb/sdk`, `@luxdb/sdk/browser`, or `@luxdb/sdk/ssr` import, method signature, and exported types in public SDK docs or installed public types; never fill gaps with ecosystem-memory names. Create the client in the right context: browser with `createBrowserClient`, SSR request handling with `createServerClient` and framework cookie adapters, trusted server with `createClient`. Use a publishable key in browser and SSR app contexts; secret keys and operator passwords remain server-side.

Implement the flow using `lux.auth`, check every result error, and clear application state after `signOut()`. For OAuth, register the exact redirect, start `signInWithOAuth`, and call `consumeOAuthRedirect()` at the callback. Use PKCE for custom-scheme callbacks. Configure providers through the dashboard or `lux auth provider`, never from untrusted app code.

Add grants in a migration before expecting users to access application tables. Grants constrain select, writes, and live subscriptions. Test as an unauthenticated client, a signed-in user who should be denied, and a user who should see only permitted rows.
