import Redis, { type RedisOptions } from 'ioredis';
import { LuxAuthClient, type LuxAuthOptions } from './auth';
import { createProjectClient, LuxProjectClient, type LuxProjectOptions } from './project';
import { TimeSeriesNamespace, VectorNamespace } from './namespaces';
import { LuxRealtimeManager } from './realtime';
import { TableQueryBuilder, type TableQueryBuilderOptions } from './table';
import type {
	KSubEvent,
	LuxSchema,
	LuxTypedRow,
	TableRow,
	TSAddOptions,
	TSMRangeResult,
	TSRangeOptions,
	TSSample,
	VSearchResult,
} from './types';

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
export {
	createProjectClient,
	LuxProjectClient,
};
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

export type LuxClientOptions = RedisOptions & LuxAuthOptions;
export type LuxAuthNamespace = Redis['auth'] & LuxAuthClient;

function createAuthNamespace(redis: Redis, options: LuxAuthOptions): LuxAuthNamespace {
	const client = new LuxAuthClient(options);
	const redisAuth = ((...args: unknown[]) => {
		return (redis as any).call('AUTH', ...args);
	}) as LuxAuthNamespace;

	return new Proxy(redisAuth, {
		get(target, prop, receiver) {
			if (prop in client) {
				const value = (client as any)[prop];
				return typeof value === 'function' ? value.bind(client) : value;
			}
			return Reflect.get(target, prop, receiver);
		},
		set(_target, prop, value) {
			(client as any)[prop] = value;
			return true;
		},
	}) as LuxAuthNamespace;
}

const EMPTY_COLS: ReadonlySet<string> = new Set<string>();

/** Pull the table name out of TSELECT args (the token after `FROM`). */
function tableFromSelectArgs(args: string[]): string | null {
	const i = args.findIndex((a) => String(a).toUpperCase() === 'FROM');
	return i >= 0 && i + 1 < args.length ? String(args[i + 1]) : null;
}

export class Lux extends Redis {
	vectors: VectorNamespace;
	timeseries: TimeSeriesNamespace;
	auth: LuxAuthNamespace;
	authApi: LuxAuthClient;
	private realtimeManager?: LuxRealtimeManager;
	/** Per-table set of JSON/ARRAY column names, so reads decode them to objects. */
	private jsonColsCache = new Map<string, Set<string>>();

	constructor(options?: LuxClientOptions | RedisOptions | string) {
		let authOptions: LuxAuthOptions = {};
		if (typeof options === 'string') {
			options = options.replace(/^luxs:\/\//, 'rediss://').replace(/^lux:\/\//, 'redis://');
		} else if (options) {
			const { httpUrl, apiKey, authToken, fetch: fetchImpl, ...redisOptions } = options as LuxClientOptions;
			authOptions = { httpUrl, apiKey, authToken, fetch: fetchImpl };
			options = redisOptions as RedisOptions;
		}
		super(options as any);
		this.vectors = new VectorNamespace(this);
		this.timeseries = new TimeSeriesNamespace(this);
		this.auth = createAuthNamespace(this, authOptions);
		this.authApi = this.auth;
	}

	table<T extends object | readonly object[] = TableRow>(
		name: string,
		options?: TableQueryBuilderOptions<LuxTypedRow<T>>,
	): TableQueryBuilder<LuxTypedRow<T>> {
		return new TableQueryBuilder<LuxTypedRow<T>>(this, name, options);
	}

	async _subscribePattern(pattern: string, handler: (event: KSubEvent) => void): Promise<() => void> {
		if (!this.realtimeManager) {
			this.realtimeManager = new LuxRealtimeManager(this);
		}
		return this.realtimeManager.subscribe(pattern, handler);
	}

	async _tselect(args: string[]): Promise<TableRow[]> {
		const result = await this.call('TSELECT', ...args) as any;
		if (!result || !Array.isArray(result)) return [];

		const jsonCols = await this.jsonColumns(tableFromSelectArgs(args));

		const rows: TableRow[] = [];
		for (const item of result) {
			if (Array.isArray(item)) {
				const row: TableRow = {};
				for (let i = 0; i < item.length - 1; i += 2) {
					const key = String(item[i]);
					let val: unknown = item[i + 1];
					// JSON / ARRAY columns come back as JSON text over RESP; decode
					// them to real objects/arrays. Leave malformed values as-is.
					if (jsonCols.has(key) && typeof val === 'string' && val !== '') {
						try {
							val = JSON.parse(val);
						} catch {
							/* not valid JSON - keep the raw string */
						}
					}
					row[key] = val as TableRow[string];
				}
				if (row.id != null && typeof row.id === 'string') {
					const parsed = Number(row.id);
					if (!Number.isNaN(parsed) && Number.isFinite(parsed)) {
						row.id = parsed;
					}
				}
				rows.push(row);
			}
		}
		return rows;
	}

	/** Resolve (and cache) the JSON/ARRAY column names for a table via TSCHEMA. */
	private async jsonColumns(table: string | null): Promise<ReadonlySet<string>> {
		if (!table) return EMPTY_COLS;
		const cached = this.jsonColsCache.get(table);
		if (cached) return cached;
		const set = new Set<string>();
		try {
			const schema = await this.call('TSCHEMA', table) as any;
			if (Array.isArray(schema)) {
				for (const entry of schema) {
					const parts = String(entry).trim().split(/\s+/);
					const name = parts[0];
					const type = (parts[1] || '').toUpperCase();
					if (name && (type === 'JSON' || type === 'ARRAY')) set.add(name);
				}
			}
		} catch {
			/* schema unavailable - values stay as strings */
		}
		this.jsonColsCache.set(table, set);
		return set;
	}

	// Vector methods (keep for backward compat)
	async vset(key: string, vector: number[], options?: { metadata?: Record<string, unknown>; ex?: number; px?: number }): Promise<'OK'> {
		const args: (string | number)[] = [key, vector.length, ...vector];
		if (options?.metadata) {
			args.push('META', JSON.stringify(options.metadata));
		}
		if (options?.ex) {
			args.push('EX', options.ex);
		} else if (options?.px) {
			args.push('PX', options.px);
		}
		return this.call('VSET', ...args) as Promise<'OK'>;
	}

	async vget(key: string): Promise<{ dims: number; vector: number[]; metadata?: Record<string, unknown> } | null> {
		const result = await this.call('VGET', key) as any;
		if (!result || !Array.isArray(result)) return null;
		const dims = parseInt(result[0], 10);
		const vector: number[] = [];
		for (let i = 1; i <= dims; i++) {
			vector.push(parseFloat(result[i]));
		}
		const metaRaw = result[dims + 1];
		let metadata: Record<string, unknown> | undefined;
		if (metaRaw) {
			try { metadata = JSON.parse(metaRaw); } catch {}
		}
		return { dims, vector, metadata };
	}

	async vsearch(query: number[], options: { k: number; filter?: { key: string; value: string }; meta?: boolean }): Promise<VSearchResult[]> {
		const args: (string | number)[] = [query.length, ...query, 'K', options.k];
		if (options.filter) {
			args.push('FILTER', options.filter.key, options.filter.value);
		}
		if (options.meta) {
			args.push('META');
		}
		const result = await this.call('VSEARCH', ...args) as any;
		if (!result || !Array.isArray(result)) return [];
		const results: VSearchResult[] = [];
		for (const item of result) {
			if (Array.isArray(item)) {
				const entry: VSearchResult = { key: item[0], similarity: parseFloat(item[1]) };
				if (options.meta && item[2]) {
					try { entry.metadata = JSON.parse(item[2]); } catch { entry.metadata = { _raw: item[2] }; }
				}
				results.push(entry);
			}
		}
		return results;
	}

	async vcard(): Promise<number> {
		return this.call('VCARD') as Promise<number>;
	}

	// Time series methods (keep for backward compat)
	async tsadd(key: string, timestamp: number | '*', value: number, options?: TSAddOptions): Promise<number> {
		const args: (string | number)[] = [key, timestamp === '*' ? '*' : timestamp, value];
		if (options?.retention != null) {
			args.push('RETENTION', options.retention);
		}
		if (options?.labels) {
			args.push('LABELS' as any);
			for (const [k, v] of Object.entries(options.labels)) {
				args.push(k, v as any);
			}
		}
		return this.call('TSADD', ...args) as Promise<number>;
	}

	async tsmadd(...entries: [string, number | '*', number][]): Promise<string> {
		const args: (string | number)[] = [];
		for (const [key, ts, val] of entries) {
			args.push(key, ts === '*' ? '*' : ts, val);
		}
		return this.call('TSMADD', ...args) as Promise<string>;
	}

	async tsget(key: string): Promise<TSSample | null> {
		const result = await this.call('TSGET', key) as any;
		if (!result || !Array.isArray(result) || result.length < 2) return null;
		return { timestamp: parseInt(result[0], 10), value: parseFloat(result[1]) };
	}

	async tsrange(key: string, from: number | '-', to: number | '+', options?: TSRangeOptions): Promise<TSSample[]> {
		const args: (string | number)[] = [key, from === '-' ? '-' : from, to === '+' ? '+' : to];
		if (options?.aggregation) {
			args.push('AGGREGATION' as any, options.aggregation.type as any, options.aggregation.bucketSize);
		}
		const result = await this.call('TSRANGE', ...args) as any;
		if (!result || !Array.isArray(result)) return [];
		return result.map((pair: any) => ({ timestamp: parseInt(pair[0], 10), value: parseFloat(pair[1]) }));
	}

	async tsmrange(from: number | '-', to: number | '+', filter: string, options?: TSRangeOptions): Promise<TSMRangeResult[]> {
		const args: (string | number)[] = [from === '-' ? '-' : from, to === '+' ? '+' : to];
		if (options?.aggregation) {
			args.push('AGGREGATION' as any, options.aggregation.type as any, options.aggregation.bucketSize);
		}
		args.push('FILTER' as any, filter as any);
		const result = await this.call('TSMRANGE', ...args) as any;
		if (!result || !Array.isArray(result)) return [];
		return result.map((series: any) => {
			const labels: Record<string, string> = {};
			if (Array.isArray(series[1])) {
				for (const pair of series[1]) {
					if (Array.isArray(pair) && pair.length >= 2) labels[pair[0]] = pair[1];
				}
			}
			const samples = Array.isArray(series[2])
				? series[2].map((s: any) => ({ timestamp: parseInt(s[0], 10), value: parseFloat(s[1]) }))
				: [];
			return { key: series[0], labels, samples };
		});
	}

	async tsinfo(key: string): Promise<Record<string, unknown>> {
		const result = await this.call('TSINFO', key) as any;
		if (!result || !Array.isArray(result)) return {};
		const info: Record<string, unknown> = {};
		for (let i = 0; i < result.length - 1; i += 2) {
			const k = result[i];
			const v = result[i + 1];
			if (k === 'labels' && Array.isArray(v)) {
				const labels: Record<string, string> = {};
				for (const pair of v) {
					if (Array.isArray(pair) && pair.length >= 2) labels[pair[0]] = pair[1];
				}
				info[k] = labels;
			} else {
				info[k] = v;
			}
		}
		return info;
	}

	// Realtime key subscriptions
	ksub(patterns: string[], handler: (event: KSubEvent) => void): { unsubscribe: () => void; connection: Redis } {
		const sub = this.duplicate();
		sub.on('error', () => {});

		const dataHandler = (sub as any)._dataHandler || (sub as any).dataHandler;
		if (dataHandler && dataHandler.returnReply) {
			const origReturn = dataHandler.returnReply.bind(dataHandler);
			dataHandler.returnReply = (reply: any) => {
				if (Array.isArray(reply) && reply.length === 4 && reply[0] === 'kmessage') {
					handler({ pattern: reply[1], key: reply[2], operation: reply[3] });
					return;
				}
				return origReturn(reply);
			};
		} else {
			const origEmit = sub.emit.bind(sub);
			(sub as any).emit = (event: string, ...args: any[]) => {
				if (event === 'error' && args[0]?.message?.includes('Command queue state error')) {
					const match = args[0].message.match(/Last reply: kmessage,([^,]+),([^,]+),(.+)/);
					if (match) {
						handler({ pattern: match[1], key: match[2], operation: match[3] });
						return true;
					}
				}
				return origEmit(event, ...args);
			};
		}

		sub.call('KSUB', ...patterns);
		return {
			connection: sub,
			unsubscribe() { sub.disconnect(); },
		};
	}
}

export function createClient<DB extends Record<string, object> = LuxSchema>(
	url: string,
	key: string,
	options?: Omit<LuxProjectOptions, 'url' | 'key'>
): LuxProjectClient<DB>;
export function createClient(options?: LuxClientOptions | RedisOptions | string): Lux;
export function createClient(
	optionsOrUrl?: LuxClientOptions | RedisOptions | string,
	key?: string,
	projectOptions?: Omit<LuxProjectOptions, 'url' | 'key'>
): Lux | LuxProjectClient<any> {
	if (typeof optionsOrUrl === 'string' && typeof key === 'string') {
		return createProjectClient({ ...(projectOptions ?? {}), url: optionsOrUrl, key });
	}
	return new Lux(optionsOrUrl);
}

export function createAuthClient(options: LuxAuthOptions): LuxAuthClient {
	return new LuxAuthClient(options);
}

export default Lux;
