// Browser-safe package root.
//
// The Node entry (`index.ts`) statically imports ioredis for the RESP `Lux`
// client, and ioredis references `process`, which crashes in browsers. Bundlers
// that honor the `"browser"` export condition resolve `@luxdb/sdk` to this file
// instead and never pull ioredis into the bundle.
//
// Everything here is HTTP/WebSocket based and runs in the browser. The RESP
// `Lux` client, `createClient(options)` server overload, and `default` export
// are Node-only; reach them from a server-side module (which resolves to the
// Node entry) or from `@luxdb/sdk` under Node conditions.

import { createProjectClient, type LuxProjectClient, type LuxProjectOptions } from './project';
import { LuxAuthClient, type LuxAuthOptions } from './auth';
import type { LuxSchema } from './types';

export type {
	LuxAuthKey,
	LuxAuthGrantRow,
	LuxAuthIdentityRow,
	LuxAuthChangeEvent,
	LuxAuthOptions,
	LuxAuthKeyRow,
	LuxAuthProviderRow,
	LuxAuthSession,
	LuxAuthSessionRow,
	LuxAuthSigningKeyRow,
	LuxAuthStateChangeCallback,
	LuxAuthStorage,
	LuxAuthSubscription,
	LuxAuthTables,
	LuxAuthUserRow,
	LuxAuthUser,
	LuxUser,
	LuxOAuthProvider,
	LuxOAuthUrl,
	LuxSignInWithOAuthOptions,
	LuxCreateApiKeyOptions,
	LuxSignInOptions,
	LuxSignUpOptions,
} from './auth';
export { createProjectClient, LuxProjectClient };
export { LuxProjectLiveSubscription } from './project';
export { createBrowserClient } from './browser';
export { LuxStorageBucketClient, LuxStorageNamespace } from './storage';
export type { LuxBrowserClientOptions } from './browser';
export { createServerClient } from './ssr';
export type {
	LuxBrowserCookieMethods,
	LuxCookie,
	LuxCookieOptions,
	LuxCookieToSet,
	LuxServerCookieMethods,
	LuxServerClientOptions,
} from './ssr';
export type {
	LuxLiveResult,
	LuxProjectLiveEvent,
	LuxProjectLiveEventType,
	LuxProjectOptions,
	LuxTableColumn,
	LuxVectorSearchOptions,
} from './project';
export type {
	LuxStorageListOptions,
	LuxStorageObject,
	LuxStorageSignOptions,
	LuxStorageUploadOptions,
} from './storage';
export type {
	KSubEvent,
	LuxAggregateRow,
	LuxAggregateValue,
	LuxError,
	LuxInferRow,
	LuxNearRow,
	LuxResult,
	LuxSimilarity,
	LuxTypedRow,
	TableChangeEvent,
	TableChangeType,
	TableErrorEvent,
	TableRow,
	TableSchema,
	TSAddOptions,
	TSMRangeResult,
	TSRangeOptions,
	TSSample,
	VSearchResult,
} from './types';
export { TableQueryBuilder, TableSubscription } from './table';
export type { TableQueryBuilderOptions } from './table';

/**
 * Browser entry point: opens an HTTP/WebSocket project client. Only the
 * `(url, key)` signature exists here; the RESP `createClient(options)` overload
 * is Node-only (it needs ioredis).
 */
export function createClient<DB extends Record<string, object> = LuxSchema>(
	url: string,
	key: string,
	options?: Omit<LuxProjectOptions, 'url' | 'key'>,
): LuxProjectClient<DB> {
	return createProjectClient<DB>({ ...(options ?? {}), url, key });
}

export function createAuthClient(options: LuxAuthOptions): LuxAuthClient {
	return new LuxAuthClient(options);
}
