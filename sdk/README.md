# @luxdb/sdk

Official TypeScript SDK for Lux.

Use the project client for browser, server, and SSR app code. Use the direct client when you want low-level Redis-compatible access to a Lux instance.

## Install

```bash
bun i @luxdb/sdk
```

## Browser app client

Use a publishable key in browser code. The browser client persists auth sessions
in the shared `lux-auth-session` cookie by default.
Like Supabase's SSR client, `createBrowserClient` returns a singleton in browser
environments, broadcasts auth changes across tabs, and recovers the cookie-backed
session when the document becomes visible. Refresh calls are coalesced within a
JavaScript realm. In browsers that support the Web Locks API, tabs also serialize
refresh work and adopt a session another tab has already rotated rather than
replaying its consumed refresh token.

```ts
import { createBrowserClient } from "@luxdb/sdk/browser";

const lux = createBrowserClient(
  "https://api.luxdb.dev/v1/my-project",
  "lux_pub_..."
);

const { data: session, error } = await lux.auth.signInWithPassword({
  email: "user@example.com",
  password: "correct horse battery staple",
});

if (error) throw error;
```

## Push notifications

Server-side callers can send to one subject or many with a secret key. Lux
derives the APNs topic and push type, routes each device to its sandbox or
production host, and validates the final APNs payload before enqueue.

```ts
import { createClient } from "@luxdb/sdk";

const lux = createClient(process.env.LUX_URL!, process.env.LUX_SECRET_KEY!);

await lux.push.send("agent-123", {
  title: "Input needed",
  body: "The agent is waiting for your answer.",
  subtitle: "Vigil",
  image: "https://example.com/question.png",
  interruption_level: "time-sensitive",
  target_content_id: "question-window",
  relevance_score: 0.9,
  filter_criteria: "work",
  apns: {
    collapse_id: "agent-123-question",
    expiration: Math.floor(Date.now() / 1000) + 300,
    priority: 10,
  },
  data: { question: { id: "q_123" }, requires_reply: true },
});
```

The supported values are `passive`, `active`, `time-sensitive`, and `critical`.
Time-sensitive notifications may break through Focus when the user allows it.
Omit `interruption_level` for the normal `active` behavior.

Images are delivered through a custom `image_url` payload field and
automatically enable APNs `mutable-content`; the iOS app needs a Notification
Service Extension that downloads the URL and attaches it to the notification.
Action buttons use `category`, which must match a category registered by the
app. Bundle localization is available through `title_loc_key`,
`subtitle_loc_key`, `body_loc_key`, and their corresponding `_loc_args`.

Critical notifications require Apple's Critical Alerts entitlement and can use
a critical sound object:

```ts
await lux.push.send("agent-123", {
  title: "Immediate action required",
  interruption_level: "critical",
  sound: { critical: true, name: "default", volume: 1 },
});
```

APNs transport options support collapse IDs, delivery expiration, and
priorities `1`, `5`, or `10`. Background-only notifications use push type
`background` and require priority `5`; other notifications use `alert`. Lux
generates a stable, unique APNs request UUID per durable outbox delivery.

## Tables

Queries and mutations return a Supabase-style result object:

```ts
interface User {
  id: number;
  email: string;
  age: number;
}

interface Message {
  id: string;
  body: string;
  embedding: number[];
}

const { data: users, error } = await lux
  .table<User[]>("users")
  .select()
  .gt("age", 25)
  .order("age", { ascending: false })
  .limit(10);

if (error) throw error;
console.log(users);
```

`table<T>()` accepts either a row type or an array type. `table<User>("users")`
and `table<User[]>("users")` both infer `User` rows; the array form is useful
when you want the generic to read like the returned data.

For computed projections, pass the projection shape to `select<T>()`:

```ts
import type { LuxAggregateRow, LuxNearRow } from "@luxdb/sdk";

type TeamStats = { team_id: number } & LuxAggregateRow<"member_count" | "avg_age">;

const { data: teamStats } = await lux
  .table<User>("members")
  .select<TeamStats>("team_id,COUNT(*) AS member_count,AVG(age) AS avg_age")
  .group("team_id");

const { data: matches } = await lux
  .table<Message>("messages")
  .select<LuxNearRow<Message>>("id,body,_similarity")
  .near("embedding", queryEmbedding, { k: 10, threshold: 0.8 });
```

Writes return the affected row(s), including server-generated columns (`id`,
UUIDv7 primary keys, `DEFAULT now()` timestamps):

```ts
// insert -> the inserted row
const { data: inserted, error: insertError } = await lux
  .table("messages")
  .insert({ body: "hello", channel: "general" });

// bulk insert in a single request -> array of rows
const { data: many } = await lux
  .table("messages")
  .insert([{ body: "a" }, { body: "b" }]);

// upsert: insert, or update the row that conflicts on `onConflict` (default: PK)
const { data: user } = await lux
  .table("users")
  .upsert({ email: "a@x.com", name: "Bob" }, { onConflict: "email" });

// update / delete -> the affected rows
const { data: updated } = await lux
  .table("messages")
  .update({ body: "edited" })
  .eq("id", inserted?.id);

const { data: deleted } = await lux
  .table("messages")
  .delete()
  .eq("id", inserted?.id);
```

### Point access by primary key

When you already know a row's primary key, skip the query builder entirely and
address the row directly with `.row(pk)`. It works for any PK type (int, UUID,
string).

```ts
// read the whole row, or a single column
const { data: user } = await lux.table<User>("users").row(123).get();
const { data: age }  = await lux.table<User>("users").row(123).get("age");

// point-update one cell, or several at once
await lux.table("users").row(123).set("age", 30);
await lux.table("users").row(123).set({ age: 30, name: "Ada" });
```

`.set()` updates an existing row (it is not an upsert) and resolves to the
updated row. On the wire this is a direct cell write, not a `WHERE` query, so it
skips the query planner — but it still runs the full table write path: column
types, unique constraints, secondary/JSON indexes, encryption, TTL, and `.live()`
change events are all enforced, and reads and writes are grant-checked exactly
like the query builder. It is a typed fast path, not raw key/value access.

### Filters and JSON

Beyond `.eq/.neq/.gt/.gte/.lt/.lte`, the query builder supports `IN` lists, JSON
dot-paths, and arrays:

```ts
await lux.table("users").select().in("id", [1, 2, 3]);
await lux.table("users").select().notIn("status", ["banned", "deleted"]);

// JSON columns round-trip as native objects (no manual JSON.stringify)
await lux.table("events").insert({ metadata: { plan: { tier: "pro" }, count: 0 } });

// Query JSON by dot-path, like a JS object. A path that does not resolve is a
// non-match, never an error.
await lux.table("events").select().eq("metadata.plan.tier", "pro");

// IS VALID is existence, not truthiness: 0 / false / "" all count as valid.
await lux.table("events").select().isValid("metadata.count");
await lux.table("events").select().isNotValid("metadata.deleted_at");

// IS NULL / IS NOT NULL on a regular column (NULL == the column is absent)
await lux.table("tasks").select().isNull("deleted_at");
await lux.table("tasks").select().isNotNull("archived_at");

// Array membership, and a declared JSON-path index for range queries at scale.
await lux.table("events").select().contains("tags", "urgent");
await lux.table("events").createIndex("metadata.plan.tier", "str");
```

## Typed client

Generate types from your schema with the CLI, then pass them to `createClient`
for end-to-end inference — no hand-written interfaces:

```bash
lux types            # writes lux/types/database.ts
```
```ts
import { createClient } from "@luxdb/sdk";
import type { Database } from "./lux/types/database";

const lux = createClient<Database>(url, key);

const { data } = await lux.table("posts").select(); // rows typed; "posts" autocompletes
data?.[0].title;                                    // ✅
// data?.[0].nope -> compile error (unknown column)
```

`table(name)` infers the row type from `Database` and autocompletes your table
names — no per-call generic. Untyped clients keep working, and the explicit
`table<Row>(name)` form is unchanged. Re-run `lux types` after a migration.

## Live tables

Browser clients can subscribe to table queries over Lux Live. The SDK opens a WebSocket to the project live endpoint, and Lux core sends a snapshot followed by insert/update/delete events for rows matching the query.

`.live()` resolves once the server confirms the subscription, returning the same
`{ data, error }` shape as the rest of the SDK (here named `{ live, error }`). If
the query isn't permitted by a read grant, `error` is populated and `live` is
`null`. The subscription is async-iterable: the buffered snapshot arrives first,
then live changes.

Async iterators buffer up to 1,024 unread events. If the limit is reached, the
SDK emits one `error` callback with code `LIVE_ITERATOR_OVERFLOW`, clears the
buffer, and ends the iterator rather than silently dropping a change. Callback
handlers remain active until `unsubscribe()`.

```ts
const { live, error } = await lux
  .table<{ id: string; channel_id: string; body: string }>("messages")
  .eq("channel_id", "general")
  .live();

if (error) throw error;

for await (const event of live) {
  if (event.type === "snapshot") console.log(event.rows);
  else console.log(event.type, event.new ?? event.old);
}
```

You can also attach callbacks instead of iterating:

```ts
const { live, error } = await lux.table("messages").eq("channel_id", "general").live();
if (error) throw error;

live
  .on("insert", (event) => console.log(event.new))
  .on("update", (event) => console.log(event.old, event.new))
  .on("delete", (event) => console.log(event.old));

await live.unsubscribe();
```

## OAuth

```ts
const { data, error } = await lux.auth.signInWithOAuth({
  provider: "google",
  redirectTo: "https://app.example.com/auth/callback",
});

if (error) throw error;
```

For Sign in with Apple on the web, configure the provider from trusted server
code with a secret project key. `apple_private_key` is the contents of the
`AuthKey_*.p8` file from Apple, not its path. Omit it on later updates to retain
the stored key.

```ts
import { createClient } from "@luxdb/sdk";

const admin = createClient(
  "https://api.example.com/v1/my-project",
  process.env.LUX_SECRET_KEY!
);

const { data: provider, error: providerError } = await admin.auth.upsertProvider({
  provider: "apple",
  apple_services_id: "com.example.web",
  apple_team_id: "TEAMID1234",
  apple_key_id: "KEYID12345",
  apple_private_key: process.env.APPLE_PRIVATE_KEY,
  apple_bundle_ids: "com.example.ios,com.example.macos",
  redirect_uri: "https://api.example.com/v1/my-project/auth/v1/callback/apple",
});

if (providerError) throw providerError;
console.log(provider.has_apple_private_key);
```

`apple_bundle_ids` is a comma-separated list of native app audiences accepted
from Apple identity tokens. It can be configured by itself for native-only
Sign in with Apple:

```ts
await admin.auth.upsertProvider({
  provider: "apple",
  apple_bundle_ids: "com.example.ios,com.example.macos",
});
```

To support web and native sign-in together, send `apple_bundle_ids` alongside
the web fields as shown in the first example. Apple upserts preserve omitted
fields, including an omitted `apple_private_key`.

For native Apple sign-in, request the one-time nonce before presenting Apple's
authorization UI. Pass the SHA-256 hash of `nonce.data.nonce` to Apple, then
exchange Apple's identity token together with the original nonce:

```ts
const nonce = await lux.auth.getAppleSignInNonce();
if (nonce.error) throw nonce.error;

const name = [
  appleCredential.fullName?.givenName,
  appleCredential.fullName?.middleName,
  appleCredential.fullName?.familyName,
].filter(Boolean).join(" ");

const result = await lux.auth.signInWithApple({
  idToken: appleCredential.identityToken,
  nonce: nonce.data.nonce,
  user: name ? { name } : undefined,
});
```

Start Apple sign-in from browser code using the same callback handling as the
other OAuth providers:

```ts
const { data, error } = await lux.auth.signInWithOAuth({
  provider: "apple",
  redirectTo: "https://app.example.com/auth/callback",
  flow: "code",
});

if (error) throw error;
```

On your callback page:

```ts
const { data, error } = await lux.auth.consumeOAuthRedirect();

if (error) throw error;
console.log(data.user);
```

Auth types are exported for app code and system table reads:

```ts
import type { LuxUser, LuxAuthTables } from "@luxdb/sdk";

type AuthUserRow = LuxAuthTables["auth.users"];

function renderUser(user: LuxUser, row: AuthUserRow) {
  return row.email ?? user.email;
}
```

## Server client

Use a secret key only from trusted server code.

```ts
import { createClient } from "@luxdb/sdk";

const admin = createClient(
  "https://api.luxdb.dev/v1/my-project",
  process.env.LUX_SECRET_KEY!
);

const { data: users, error } = await admin.auth.listUsers();
```

## SSR client

Use `createServerClient` with your framework's cookie methods to persist sessions on the server.
The SSR and browser clients share the `lux-auth-session` cookie by default, so a
session created in a SvelteKit action is available to the browser client after
the response is applied.

```ts
import { createServerClient } from "@luxdb/sdk/ssr";

const lux = createServerClient(
  "https://api.luxdb.dev/v1/my-project",
  "lux_pub_...",
  { cookies }
);
```

In SvelteKit, create the server client with the request-local `cookies` object:

```ts
// src/hooks.server.ts or +page.server.ts
const lux = createServerClient(url, publishableKey, {
  cookies: {
    getAll: () => cookies.getAll(),
    setAll: (cookiesToSet) => {
      cookiesToSet.forEach(({ name, value, options }) => {
        cookies.set(name, value, options);
      });
    },
  },
});
```

`setAll` batches cookie updates and every item always includes concrete cookie
options. When your framework adapter also controls response headers, apply the
second `headers` argument to the response; Lux supplies private/no-store headers
for responses that update auth cookies.

On server contexts that can only read request cookies, `setAll` may be omitted.
The client can read the existing session, but sign-in, refresh, and sign-out
cookie changes cannot be persisted from that context.

The default session cookie is intentionally not `HttpOnly`, because the browser
client must read it and refresh the session. Override `auth.storage` on the
browser client if you want a different persistence strategy.

## Direct Lux/Redis-compatible access

Use direct access for trusted infrastructure that needs RESP commands, low-level primitives, or compatibility with Redis workflows. Do not ship database passwords to browsers.

```ts
import Lux from "@luxdb/sdk";

const lux = new Lux("lux://:password@localhost:6379");

await lux.set("hello", "world");
const value = await lux.get("hello");
```

## Access model

- `lux_pub_...` keys are safe for browser app calls.
- `lux_sec_...` keys are server-only.
- User sessions issue JWT access tokens.
- Browser live subscriptions use the project publishable key plus the signed-in user's JWT.
- Table `select()` accepts Lux's constrained projection grammar, not arbitrary SQL.
- Direct `lux://` or `rediss://` database access uses the database password and is for trusted infrastructure.
- With auth enabled, signed-in users are denied by default and gated by per-table **grants** (`GRANT read, write ON t WHERE user_id = auth.uid()`). Reads, writes, and `.live()` are all checked against the grant: a query or subscription must satisfy the predicate or it is rejected (an unscoped `.live()` under a row-scoped grant fails at subscribe time). Grants are authored as migrations.
