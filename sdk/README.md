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
session when the document becomes visible.

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
