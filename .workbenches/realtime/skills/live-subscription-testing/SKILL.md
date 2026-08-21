---
name: live-subscription-testing
description: Use when adding or debugging a table `.live()` subscription, realtime UI state, reconnect behavior, iterator overflow, cleanup, or RESP KSUB handling.
---

# Lux Live UI Sync

Start with the requested subscription's minimal runnable path. Verify every TypeScript import, method signature, and exported type in public SDK docs or installed public types before emitting code. Use only `@luxdb/sdk`, `@luxdb/sdk/browser`, or `@luxdb/sdk/ssr`; never invent an ecosystem-memory package or API. Build a subscription from the same filtered query that renders the screen. Await `.live()`, handle an error before rendering as subscribed, replace local state from the initial `snapshot`, then reduce insert, update, and delete events by primary key. Unsubscribe during component teardown or job shutdown.

Assume a disconnect can require a snapshot-based resync. The SDK reconnects and resubscribes, but does not document exactly-once or durable event delivery. If using the async iterator, consume it promptly and handle `LIVE_ITERATOR_OVERFLOW` by rebuilding state; callback subscriptions remain active until `unsubscribe()`.

Use `KSUB` only for trusted key-pattern mutation reactions. It emits `["kmessage", pattern, key, operation]`, not query-filtered rows. Confirm browser subscriptions are authenticated and permitted by the appropriate read grant; route grant design to `auth`.
