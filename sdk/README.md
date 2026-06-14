# @luxdb/sdk

Official TypeScript SDK for Lux.

Use the project client for browser, server, and SSR app code. Use the direct client when you want low-level Redis-compatible access to a Lux instance.

## Install

```bash
bun i @luxdb/sdk
```

## Browser app client

Use a publishable key in browser code. The browser client persists auth sessions in browser storage by default.

```ts
import { createBrowserClient } from "@luxdb/sdk";

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

```ts
const { data: inserted, error: insertError } = await lux
  .table("messages")
  .insert({ body: "hello", channel: "general" });

const { data: updated, error: updateError } = await lux
  .table("messages")
  .update({ body: "edited" })
  .eq("id", inserted?.id);

const { data: deleted, error: deleteError } = await lux
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

// Array membership, and a declared JSON-path index for range queries at scale.
await lux.table("events").select().contains("tags", "urgent");
await lux.table("events").createIndex("metadata.plan.tier", "str");
```

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

```ts
import { createServerClient } from "@luxdb/sdk";

const lux = createServerClient(
  "https://api.luxdb.dev/v1/my-project",
  "lux_pub_...",
  { cookies }
);
```

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
