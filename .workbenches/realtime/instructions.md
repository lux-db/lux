# Lux Application Realtime

Help consumers build live application behavior with public Lux table subscriptions or RESP key subscriptions. Lead with the minimal runnable subscription for the requested boundary and expand only for a material delivery risk or user request. Do not inspect or modify Lux engine internals unless the user explicitly asks to contribute to Lux itself. Use `sdk/README.md`, installed public `@luxdb/sdk` types, and `README.md` as authority.

Before emitting runnable TypeScript, verify exact package names, method signatures, and exported types in public SDK docs/types. Valid SDK package paths are only `@luxdb/sdk`, `@luxdb/sdk/browser`, and `@luxdb/sdk/ssr`; never substitute ecosystem-memory names. If SDK tooling is unavailable, provide unexecuted `npm`, `pnpm`, `yarn`, or `bun` installation commands rather than refusing to help.

Choose the model explicitly. Use `table(...).select()/filters.live()` for a browser or app UI that needs an initial query snapshot and matching insert, update, and delete events. Use direct RESP `KSUB`/`KUNSUB` for trusted infrastructure reacting to key-pattern mutations; each event is `["kmessage", pattern, key, operation]`, not a table row. Do not substitute one for the other.

Await `.live()` and handle its `{ live, error }` result before updating UI state. Apply the snapshot first, handle event types explicitly, and always call `unsubscribe()` when the component, request, or worker ends. The SDK reconnects and resubscribes after a socket closes or auth changes; make UI reducers idempotent and be prepared to rebuild state from the next snapshot. Async iteration has a 1,024-event unread buffer and ends with `LIVE_ITERATOR_OVERFLOW`; use callbacks or a resync strategy when consumption can lag.

Pick this package when subscriptions, lifecycle cleanup, reconnects, or UI synchronization are central. Coordinate with `auth` when browser subscriptions need a session or row grants, and with `core` only for the underlying table query. Do not promise exactly-once delivery, durable cursors, or lossless reconnects.
