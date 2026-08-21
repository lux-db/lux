---
name: push-delivery-safety
description: Use when configuring APNs or VAPID, registering devices, sending Lux push notifications, targeting subjects, or investigating delivery setup and payload problems.
---

# Lux Push Integration

Start with the requested platform's minimal integration. The repository documents the TypeScript SDK only: native iOS acquires an APNs token through platform-native APIs first, then crosses the documented Lux boundary; never invent a Swift Lux SDK. Before emitting code, verify imports, signatures, and exported types in public `@luxdb/sdk` docs/types. Before emitting commands, verify public CLI docs or installed `lux push --help`. Do not print, commit, or copy provider private keys into application configuration.

Use exact local-versus-Cloud forms: `lux push status --check` is local and `lux push status my-app --check` is positional Cloud. Initial local and Cloud APNs setup requires a key file: use `lux push apns set --team-id TEAM_ID --key-id KEY_ID --topic com.example.app --environment sandbox --p8-file AuthKey_KEY_ID.p8` locally, or `lux push apns set my-app --team-id TEAM_ID --key-id KEY_ID --topic com.example.app --environment production --p8-file AuthKey_KEY_ID.p8` for Cloud. Later metadata-only APNs updates may omit `--p8-file` to preserve the existing encrypted key. Enable local VAPID with `lux push vapid enable --subject mailto:push@example.com` or Cloud VAPID with `lux push vapid enable my-app --subject mailto:push@example.com`. Use the same positional placement for invalidating Cloud commands: `lux push vapid rotate my-app --subject mailto:push@example.com --yes`, `lux push vapid disable my-app --yes`, and `lux push apns clear my-app --yes`.

Register a device after a user session is available with `lux.push.register(options)`; use `lux.push.registerFor(subjectId, options)` only in trusted server code. Use `unregister(id)`, `unregisterByToken(token)`, and `devices(subjectId?)` at their documented key boundaries. Web clients should use `getVapidPublicKey()` or `subscribeWebPush(options)` with an active service worker and user permission. Keep the opaque subject stable, unregister stale tokens, and preserve `sandbox` versus `production` APNs environment.

Send from trusted server code using `lux.push.send(subjects, notification)`. Its `{ enqueued }` result confirms only durable enqueue, not provider acceptance, device delivery, or display. Validate app-side requirements: an iOS service extension for images, registered categories for actions, and Apple entitlement for critical alerts. For Web Push, require a service worker and notification permission, and re-subscribe clients after `lux push vapid rotate --subject mailto:push@example.com --yes`.
