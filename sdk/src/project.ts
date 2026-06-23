import { LuxAuthClient, type LuxAuthOptions } from './auth';
import { LuxStorageNamespace } from './storage';
import type { LuxError, LuxResult, LuxSchema, LuxTypedRow } from './types';
import { err, ok, toLuxError } from './utils';

export interface LuxProjectOptions {
	url: string;
	key: string;
	fetch?: typeof fetch;
	websocket?: typeof WebSocket;
	auth?: Omit<LuxAuthOptions, 'httpUrl' | 'apiKey' | 'fetch'>;
}

export interface LuxTableColumn {
	name: string;
	type: 'STR' | 'INT' | 'FLOAT' | 'BOOL' | 'TIMESTAMP' | 'UUID' | `VECTOR(${number})`;
	primaryKey?: boolean;
	unique?: boolean;
	notNull?: boolean;
	references?: string;
	onDelete?: string;
}

export interface LuxVectorSearchOptions {
	vector: number[];
	k?: number;
	filter?: string;
	filter_value?: string;
}

type QueryValue = string | number | boolean | number[] | null;
type FilterOperator =
	| 'eq'
	| 'neq'
	| 'gt'
	| 'gte'
	| 'lt'
	| 'lte'
	| 'is'
	| 'in'
	| 'notIn'
	| 'isValid'
	| 'isNotValid'
	| 'isNull'
	| 'isNotNull'
	| 'contains';
type ProjectRowInput<T extends object> = Partial<T> & Record<string, QueryValue>;
type ProjectSelectSingle<TResult> = TResult extends readonly (infer Row)[] ? Row : TResult;

interface QueryFilter {
	column: string;
	operator: FilterOperator;
	value: QueryValue | QueryValue[];
}

interface QueryOrder {
	column: string;
	ascending: boolean;
}

interface QueryJoin {
	type: 'inner' | 'left';
	table: string;
	alias: string;
	onLeft: string;
	onRight: string;
}

interface QueryHaving {
	column: string;
	operator: FilterOperator;
	value: QueryValue;
}

interface QueryNear {
	field: string;
	vector: number[];
	k: number;
	threshold?: number;
}

export type LuxProjectLiveEventType = 'snapshot' | 'insert' | 'update' | 'delete' | 'error';

export interface LuxProjectLiveEvent<T extends object = Record<string, unknown>> {
	type: LuxProjectLiveEventType;
	table: string;
	pk?: string;
	new: T | null;
	old: T | null;
	rows?: T[];
	changed?: string[];
	raw?: unknown;
	error?: { code?: string; message?: string };
}

type LiveEventHandler<T extends object> = (event: LuxProjectLiveEvent<T>) => void;

/**
 * Result of opening a live subscription, in the same `{ data, error }` spirit as
 * the rest of the SDK: `live` is the established subscription (or `null` if the
 * server rejected it), `error` carries the rejection (e.g. a grant `FORBIDDEN`).
 */
export interface LuxLiveResult<T extends object> {
	live: LuxProjectLiveSubscription<T> | null;
	error: LuxError | null;
}

interface LiveSubscriptionRecord {
	id: string;
	spec: Record<string, unknown>;
	handler: (event: unknown) => void;
	error: (error: { code?: string; message?: string }) => void;
}

export class LuxProjectClient<DB extends Record<string, object> = LuxSchema> {
	readonly url: string;
	readonly key: string;
	readonly auth: LuxAuthClient;
	readonly storage: LuxStorageNamespace;
	private fetchImpl: typeof fetch;
	private WebSocketImpl?: typeof WebSocket;
	private liveSocket: WebSocket | null = null;
	private liveSubscriptions = new Map<string, LiveSubscriptionRecord>();
	private livePending: string[] = [];

	constructor(options: LuxProjectOptions) {
		this.url = options.url.replace(/\/+$/, '');
		this.key = options.key;
		this.fetchImpl = resolveFetch(options.fetch);
		this.WebSocketImpl = options.websocket;
		this.auth = new LuxAuthClient({
			...options.auth,
			httpUrl: this.url,
			apiKey: this.key,
			fetch: this.fetchImpl,
		});
		this.storage = new LuxStorageNamespace(this);
	}

	/**
	 * Typed table accessor. When the client is created with a schema
	 * (`createClient<Database>(...)`), the table name autocompletes and the row
	 * type is inferred — no per-call generic. Otherwise pass the row type
	 * explicitly: `table<Row>(name)`.
	 */
	table<K extends keyof DB & string>(name: K): LuxProjectTable<DB[K]>;
	table<T extends object | readonly object[] = Record<string, unknown>>(
		name: string
	): LuxProjectTable<LuxTypedRow<T>>;
	table(name: string): LuxProjectTable<any> {
		return new LuxProjectTable<any>(this, name);
	}

	async ping(): Promise<LuxResult<unknown>> {
		return this.request('GET', '/ping');
	}

	async createTable(name: string, columns: Array<string | LuxTableColumn>): Promise<LuxResult<unknown>> {
		return this.request('POST', '/tables', { name, columns });
	}

	async exec(command: string | string[]): Promise<LuxResult<unknown>> {
		return this.request('POST', '/exec', { command });
	}

	async vectorSet(key: string, vector: number[], metadata?: Record<string, unknown>): Promise<LuxResult<unknown>> {
		return this.request('POST', `/vectors/${encodeURIComponent(key)}`, { vector, metadata });
	}

	async vectorSearch(options: LuxVectorSearchOptions): Promise<LuxResult<unknown>> {
		return this.request('POST', '/vectors/search', {
			vector: options.vector,
			k: options.k ?? 10,
			filter: options.filter,
			filter_value: options.filter_value,
		});
	}

	async tsAdd(key: string, value: number, options?: { timestamp?: number | '*'; labels?: Record<string, string>; retention?: number }): Promise<LuxResult<unknown>> {
		return this.request('POST', `/ts/${encodeURIComponent(key)}`, {
			timestamp: options?.timestamp ?? '*',
			value,
			labels: options?.labels,
			retention: options?.retention,
		});
	}

	async tsRange(key: string, options?: { from?: number | '-'; to?: number | '+'; count?: number }): Promise<LuxResult<unknown>> {
		const params = new URLSearchParams();
		if (options?.from != null) params.set('from', String(options.from));
		if (options?.to != null) params.set('to', String(options.to));
		if (options?.count != null) params.set('count', String(options.count));
		const query = params.toString();
		return this.request('GET', `/ts/${encodeURIComponent(key)}${query ? `?${query}` : ''}`);
	}

	async request<T = unknown>(method: string, path: string, body?: unknown): Promise<LuxResult<T>> {
		try {
			const accessToken = await this.auth.getAccessToken();
			const headers: Record<string, string> = {
				Accept: 'application/json',
				apikey: this.key,
				Authorization: `Bearer ${accessToken ?? this.key}`,
			};
			const init: RequestInit = { method, headers };
			if (body !== undefined) {
				headers['Content-Type'] = 'application/json';
				init.body = JSON.stringify(body);
			}

			const response = await this.fetchImpl(`${this.url}${path}`, init);
			const text = await response.text();
			const payload = text ? JSON.parse(text) : {};
			if (!response.ok) {
				return err(
					'LUX_PROJECT_REQUEST_ERROR',
					payload?.error || `Lux request failed with HTTP ${response.status}`,
					{ status: response.status, payload },
				);
			}
			return ok(payload as T);
		} catch (error) {
			return err('LUX_PROJECT_REQUEST_ERROR', 'Lux request failed', toLuxError(error));
		}
	}

	async fetchRaw(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
		return this.fetchImpl(input, init);
	}

	async _subscribeLive(
		spec: Record<string, unknown>,
		handler: (event: unknown) => void,
		error: (error: { code?: string; message?: string }) => void,
	): Promise<() => void> {
		const id = `sub_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;
		const record: LiveSubscriptionRecord = { id, spec, handler, error };
		this.liveSubscriptions.set(id, record);
		await this.ensureLiveSocket();
		this.sendLive({
			type: 'live.subscribe',
			id,
			spec,
		});
		return () => {
			this.liveSubscriptions.delete(id);
			this.sendLive({ type: 'live.unsubscribe', id });
			if (this.liveSubscriptions.size === 0) {
				this.liveSocket?.close();
				this.liveSocket = null;
			}
		};
	}

	private async ensureLiveSocket(): Promise<void> {
		const WebSocketImpl = resolveWebSocket(this.WebSocketImpl);
		this.WebSocketImpl = WebSocketImpl;
		if (
			this.liveSocket &&
			(this.liveSocket.readyState === WebSocketImpl.OPEN ||
				this.liveSocket.readyState === WebSocketImpl.CONNECTING)
		) {
			return;
		}

		const accessToken = await this.auth.getAccessToken();
		const url = new URL(`${this.url}/live`);
		url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
		url.searchParams.set('apikey', this.key);
		if (accessToken) url.searchParams.set('access_token', accessToken);

		const socket = new WebSocketImpl(url.toString());
		this.liveSocket = socket;

		socket.onopen = () => {
			for (const message of this.livePending.splice(0)) socket.send(message);
		};

		socket.onmessage = (event) => {
			let message: any;
			try {
				message = JSON.parse(String(event.data));
			} catch {
				return;
			}

			const subscription = typeof message.id === 'string' ? this.liveSubscriptions.get(message.id) : null;
			if (message.type === 'live.event' && subscription) {
				subscription.handler(message.event);
				return;
			}
			if (message.type === 'live.error') {
				const target = subscription ? [subscription] : [...this.liveSubscriptions.values()];
				for (const sub of target) {
					sub.error(message.error || { code: 'LIVE_ERROR', message: 'Live subscription failed' });
				}
			}
		};

		socket.onerror = () => {
			for (const subscription of this.liveSubscriptions.values()) {
				subscription.error({ code: 'LIVE_SOCKET_ERROR', message: 'Live socket failed' });
			}
		};

		socket.onclose = () => {
			if (this.liveSocket === socket) this.liveSocket = null;
			if (this.liveSubscriptions.size > 0) {
				for (const subscription of this.liveSubscriptions.values()) {
					this.livePending.push(JSON.stringify({
						type: 'live.subscribe',
						id: subscription.id,
						spec: subscription.spec,
					}));
				}
				setTimeout(() => {
					void this.ensureLiveSocket();
				}, 1000);
			}
		};
	}

	private sendLive(message: Record<string, unknown>): void {
		const payload = JSON.stringify(message);
		const WebSocketImpl = this.WebSocketImpl;
		if (WebSocketImpl && this.liveSocket?.readyState === WebSocketImpl.OPEN) {
			this.liveSocket.send(payload);
			return;
		}
		this.livePending.push(payload);
	}
}

export class LuxProjectTable<T extends object> {
	constructor(private client: LuxProjectClient<any>, private name: string) {}

	select<TResult extends object = T>(columns = '*'): LuxProjectSelectBuilder<T, TResult[]> {
		return new LuxProjectSelectBuilder<T, TResult[]>(this.client, this.name, columns);
	}

	eq(column: string, value: QueryValue): LuxProjectSelectBuilder<T, T[]> {
		return this.select().eq(column, value);
	}

	neq(column: string, value: QueryValue): LuxProjectSelectBuilder<T, T[]> {
		return this.select().neq(column, value);
	}

	gt(column: string, value: QueryValue): LuxProjectSelectBuilder<T, T[]> {
		return this.select().gt(column, value);
	}

	gte(column: string, value: QueryValue): LuxProjectSelectBuilder<T, T[]> {
		return this.select().gte(column, value);
	}

	lt(column: string, value: QueryValue): LuxProjectSelectBuilder<T, T[]> {
		return this.select().lt(column, value);
	}

	lte(column: string, value: QueryValue): LuxProjectSelectBuilder<T, T[]> {
		return this.select().lte(column, value);
	}

	near(column: string, vector: number[], options: { k?: number; threshold?: number } = {}): LuxProjectSelectBuilder<T, T[]> {
		return this.select().near(column, vector, options);
	}

	is(column: string, value: QueryValue): LuxProjectSelectBuilder<T, T[]> {
		return this.select().is(column, value);
	}

	live(): Promise<LuxLiveResult<T>> {
		return this.select<T>().live() as Promise<LuxLiveResult<T>>;
	}

	insert(row: ProjectRowInput<T>, options?: { ttl?: number }): LuxProjectInsertBuilder<unknown>;
	insert(
		rows: Array<ProjectRowInput<T>>,
		options?: { ttl?: number },
	): LuxProjectInsertBuilder<unknown[]>;
	insert(
		rowOrRows: ProjectRowInput<T> | Array<ProjectRowInput<T>>,
		options?: { ttl?: number },
	): LuxProjectInsertBuilder<unknown | unknown[]> {
		return new LuxProjectInsertBuilder(this.client, this.name, rowOrRows, { ttl: options?.ttl });
	}

	upsert(
		row: ProjectRowInput<T>,
		options?: { onConflict?: string; ttl?: number },
	): LuxProjectInsertBuilder<unknown>;
	upsert(
		rows: Array<ProjectRowInput<T>>,
		options?: { onConflict?: string; ttl?: number },
	): LuxProjectInsertBuilder<unknown[]>;
	upsert(
		rowOrRows: ProjectRowInput<T> | Array<ProjectRowInput<T>>,
		options?: { onConflict?: string; ttl?: number },
	): LuxProjectInsertBuilder<unknown | unknown[]> {
		return new LuxProjectInsertBuilder(this.client, this.name, rowOrRows, {
			upsert: true,
			onConflict: options?.onConflict,
			ttl: options?.ttl,
		});
	}

	update(patch: ProjectRowInput<T>): LuxProjectMutationBuilder<unknown> {
		return new LuxProjectMutationBuilder(this.client, this.name, 'PATCH', patch);
	}

	delete(): LuxProjectMutationBuilder<unknown> {
		return new LuxProjectMutationBuilder(this.client, this.name, 'DELETE');
	}

	async count(): Promise<LuxResult<number>> {
		const result = await this.client.request('GET', `/tables/${encodeURIComponent(this.name)}/count`);
		if (result.error) return result as LuxResult<number>;
		return ok(unwrapResult<number>(result.data) ?? 0);
	}
}

abstract class LuxProjectThenable<TResult> implements PromiseLike<LuxResult<TResult>> {
	then<TFulfilled = LuxResult<TResult>, TRejected = never>(
		onfulfilled?: ((value: LuxResult<TResult>) => TFulfilled | PromiseLike<TFulfilled>) | null,
		onrejected?: ((reason: unknown) => TRejected | PromiseLike<TRejected>) | null,
	): Promise<TFulfilled | TRejected> {
		return this.execute().then(onfulfilled, onrejected);
	}

	catch<TRejected = never>(
		onrejected?: ((reason: unknown) => TRejected | PromiseLike<TRejected>) | null,
	): Promise<LuxResult<TResult> | TRejected> {
		return this.execute().catch(onrejected);
	}

	finally(onfinally?: (() => void) | null): Promise<LuxResult<TResult>> {
		return this.execute().finally(onfinally ?? undefined);
	}

	abstract execute(): Promise<LuxResult<TResult>>;
}

abstract class LuxProjectFilterBuilder<TResult, TSelf> extends LuxProjectThenable<TResult> {
	protected filters: QueryFilter[] = [];
	protected orderBy?: QueryOrder;
	protected joins: QueryJoin[] = [];
	protected groupColumns: string[] = [];
	protected havingFilters: QueryHaving[] = [];
	protected nearQuery?: QueryNear;
	protected limitCount?: number;
	protected offsetCount?: number;

	protected constructor(
		protected client: LuxProjectClient<any>,
		protected tableName: string,
	) {
		super();
	}

	eq(column: string, value: QueryValue): TSelf {
		return this.addFilter(column, 'eq', value);
	}

	neq(column: string, value: QueryValue): TSelf {
		return this.addFilter(column, 'neq', value);
	}

	gt(column: string, value: QueryValue): TSelf {
		return this.addFilter(column, 'gt', value);
	}

	gte(column: string, value: QueryValue): TSelf {
		return this.addFilter(column, 'gte', value);
	}

	lt(column: string, value: QueryValue): TSelf {
		return this.addFilter(column, 'lt', value);
	}

	lte(column: string, value: QueryValue): TSelf {
		return this.addFilter(column, 'lte', value);
	}

	is(column: string, value: QueryValue): TSelf {
		// `.is(col, null)` is the Supabase-style spelling of an IS NULL check.
		if (value === null) return this.addFilter(column, 'isNull', '');
		return this.addFilter(column, 'is', value);
	}

	isNull(column: string): TSelf {
		return this.addFilter(column, 'isNull', '');
	}

	isNotNull(column: string): TSelf {
		return this.addFilter(column, 'isNotNull', '');
	}

	in(column: string, values: QueryValue[]): TSelf {
		return this.addFilter(column, 'in', values);
	}

	notIn(column: string, values: QueryValue[]): TSelf {
		return this.addFilter(column, 'notIn', values);
	}

	isValid(column: string): TSelf {
		return this.addFilter(column, 'isValid', '');
	}

	isNotValid(column: string): TSelf {
		return this.addFilter(column, 'isNotValid', '');
	}

	contains(column: string, value: QueryValue): TSelf {
		return this.addFilter(column, 'contains', value);
	}

	join(table: string, alias: string, onLeft: string, onRight: string): TSelf {
		this.joins.push({ type: 'inner', table, alias, onLeft, onRight });
		return this as unknown as TSelf;
	}

	leftJoin(table: string, alias: string, onLeft: string, onRight: string): TSelf {
		this.joins.push({ type: 'left', table, alias, onLeft, onRight });
		return this as unknown as TSelf;
	}

	group(columns: string | string[]): TSelf {
		this.groupColumns = Array.isArray(columns)
			? columns
			: columns.split(',').map((column) => column.trim()).filter(Boolean);
		return this as unknown as TSelf;
	}

	having(column: string, operator: FilterOperator, value: QueryValue): TSelf {
		this.havingFilters.push({ column, operator, value });
		return this as unknown as TSelf;
	}

	protected addFilter(
		column: string,
		operator: FilterOperator,
		value: QueryValue | QueryValue[],
	): TSelf {
		this.filters.push({ column, operator, value });
		return this as unknown as TSelf;
	}

	protected filteredQueryParams(): URLSearchParams {
		const params = new URLSearchParams();
		if (this.filters.length) params.set('where', filtersToWhere(this.filters));
		for (const join of this.joins) {
			const kind = join.type === 'left' ? ':left' : '';
			params.append('join', `${join.table}:${join.alias}${kind}:on(${join.onLeft}=${join.onRight})`);
		}
		if (this.groupColumns.length) params.set('group', this.groupColumns.join(','));
		if (this.havingFilters.length) params.set('having', havingToWhere(this.havingFilters));
		if (this.nearQuery) {
			params.set('near_field', this.nearQuery.field);
			params.set('near_vector', `[${this.nearQuery.vector.join(',')}]`);
			params.set('near_k', String(this.nearQuery.k));
			if (this.nearQuery.threshold != null) {
				params.set('near_threshold', String(this.nearQuery.threshold));
			}
		}
		if (this.orderBy) {
			params.set('order', `${this.orderBy.column} ${this.orderBy.ascending ? 'ASC' : 'DESC'}`);
		}
		if (this.limitCount != null) params.set('limit', String(this.limitCount));
		if (this.offsetCount != null) params.set('offset', String(this.offsetCount));
		return params;
	}
}

export class LuxProjectSelectBuilder<T extends object, TResult> extends LuxProjectFilterBuilder<TResult, LuxProjectSelectBuilder<T, TResult>> {
	private expectSingle = false;

	constructor(
		client: LuxProjectClient<any>,
		tableName: string,
		private columns: string,
	) {
		super(client, tableName);
	}

	order(column: string, options: { ascending?: boolean } = {}): this {
		this.orderBy = { column, ascending: options.ascending ?? true };
		return this;
	}

	near(column: string, vector: number[], options: { k?: number; threshold?: number } = {}): this {
		this.nearQuery = {
			field: column,
			vector,
			k: options.k ?? 10,
			threshold: options.threshold,
		};
		return this;
	}

	limit(count: number): this {
		this.limitCount = count;
		return this;
	}

	range(from: number, to: number): this {
		this.offsetCount = from;
		this.limitCount = Math.max(0, to - from + 1);
		return this;
	}

	single(): LuxProjectSelectBuilder<T, ProjectSelectSingle<TResult>> {
		this.expectSingle = true;
		if (this.limitCount == null) this.limitCount = 1;
		return this as unknown as LuxProjectSelectBuilder<T, ProjectSelectSingle<TResult>>;
	}

	async execute(): Promise<LuxResult<TResult>> {
		const params = this.filteredQueryParams();
		if (this.columns && this.columns !== '*') params.set('select', this.columns);
		const query = params.toString();
		const result = await this.client.request(
			'GET',
			`/tables/${encodeURIComponent(this.tableName)}${query ? `?${query}` : ''}`,
		);
		if (result.error) return result as LuxResult<TResult>;

		const rows = unwrapRows<T>(result.data);
		if (!this.expectSingle) {
			return ok(rows as TResult);
		}
		if (rows.length === 0) {
			return err('NOT_FOUND', `No rows found in table '${this.tableName}'`);
		}
		return ok(rows[0] as unknown as TResult);
	}

	async live(): Promise<LuxLiveResult<LuxTypedRow<TResult>>> {
		const live = new LuxProjectLiveSubscription<LuxTypedRow<TResult>>(
			this.client,
			this.tableName,
			this.columns,
			this.filters,
			this.joins,
			this.nearQuery,
			this.orderBy,
			this.limitCount,
			this.offsetCount,
		);
		const error = await live.start();
		if (error) {
			await live.unsubscribe();
			return { live: null, error };
		}
		return { live, error: null };
	}
}

export class LuxProjectLiveSubscription<T extends object> {
	private handlers: Record<LuxProjectLiveEventType | 'change', Array<LiveEventHandler<T>>> = {
		snapshot: [],
		insert: [],
		update: [],
		delete: [],
		error: [],
		change: [],
	};
	private unsubscribeFn: (() => void) | null = null;
	// Async-iterator plumbing: events buffer in `queue` until a `for await`
	// consumer pulls them; pending `next()` calls park in `waiters`.
	private queue: LuxProjectLiveEvent<T>[] = [];
	private waiters: Array<(r: IteratorResult<LuxProjectLiveEvent<T>>) => void> = [];
	private closed = false;

	constructor(
		private client: LuxProjectClient<any>,
		private table: string,
		private columns: string,
		private filters: QueryFilter[],
		private joins: QueryJoin[],
		private nearQuery?: QueryNear,
		private orderBy?: QueryOrder,
		private limitCount?: number,
		private offsetCount?: number,
	) {}

	on(type: LuxProjectLiveEventType | 'change', handler: LiveEventHandler<T>): this {
		this.handlers[type].push(handler);
		return this;
	}

	async unsubscribe(): Promise<void> {
		this.unsubscribeFn?.();
		this.unsubscribeFn = null;
		this.close();
	}

	/**
	 * Open the subscription and wait for the server to confirm it. Resolves
	 * `null` once the initial snapshot arrives, or a `LuxError` if the
	 * subscription is rejected (e.g. a grant `FORBIDDEN`) or the socket fails.
	 * Subsequent errors after a successful start surface via `on('error')` and
	 * end the async iterator.
	 */
	async start(): Promise<LuxError | null> {
		let settled = false;
		let settle!: (error: LuxError | null) => void;
		const ready = new Promise<LuxError | null>((resolve) => {
			settle = (error) => {
				if (settled) return;
				settled = true;
				resolve(error);
			};
		});

		// Safety net: a server that never answers shouldn't hang the caller.
		const timeout = setTimeout(() => {
			settle({ code: 'LIVE_TIMEOUT', message: 'Timed out establishing live subscription' });
		}, 15000);

		this.unsubscribeFn = await this.client._subscribeLive(
			this.spec(),
			(event) => {
				const kind = (event as { kind?: string })?.kind;
				this.handleEvent(event);
				if (kind === 'snapshot') settle(null);
			},
			(error) => {
				const luxError: LuxError = {
					code: error.code ?? 'LIVE_ERROR',
					message: error.message ?? 'Live subscription failed',
				};
				if (settled) {
					// Post-start failure: notify handlers and end the stream.
					this.emit({ type: 'error', table: this.table, new: null, old: null, error });
					this.close();
				} else {
					settle(luxError);
				}
			},
		);

		const result = await ready;
		clearTimeout(timeout);
		return result;
	}

	[Symbol.asyncIterator](): AsyncIterator<LuxProjectLiveEvent<T>> {
		return {
			next: (): Promise<IteratorResult<LuxProjectLiveEvent<T>>> => {
				const buffered = this.queue.shift();
				if (buffered) return Promise.resolve({ value: buffered, done: false });
				if (this.closed) return Promise.resolve({ value: undefined as never, done: true });
				return new Promise((resolve) => this.waiters.push(resolve));
			},
			return: (): Promise<IteratorResult<LuxProjectLiveEvent<T>>> => {
				void this.unsubscribe();
				return Promise.resolve({ value: undefined as never, done: true });
			},
		};
	}

	private close(): void {
		if (this.closed) return;
		this.closed = true;
		for (const waiter of this.waiters.splice(0)) {
			waiter({ value: undefined as never, done: true });
		}
	}

	private spec(): Record<string, unknown> {
		const spec: Record<string, unknown> = {
			kind: 'table',
			table: this.table,
			select: this.columns,
		};
		if (this.filters.length) {
			spec.where = this.filters.map((filter) => ({
				field: filter.column,
				op: filterOperatorToWhere(filter.operator),
				value: filter.value,
			}));
		}
		if (this.joins.length) {
			spec.joins = this.joins.map((join) => ({
				type: join.type,
				table: join.table,
				alias: join.alias,
				onLeft: join.onLeft,
				onRight: join.onRight,
			}));
		}
		if (this.nearQuery) {
			spec.near = {
				field: this.nearQuery.field,
				vector: this.nearQuery.vector,
				k: this.nearQuery.k,
				threshold: this.nearQuery.threshold,
			};
		}
		if (this.orderBy) {
			spec.orderBy = {
				field: this.orderBy.column,
				dir: this.orderBy.ascending ? 'asc' : 'desc',
			};
		}
		if (this.limitCount != null) spec.limit = this.limitCount;
		if (this.offsetCount != null) spec.offset = this.offsetCount;
		return spec;
	}

	private handleEvent(raw: unknown): void {
		if (!raw || typeof raw !== 'object') return;
		const event = raw as Record<string, any>;
		if (event.kind === 'snapshot') {
			this.emit({
				type: 'snapshot',
				table: this.table,
				new: null,
				old: null,
				rows: Array.isArray(event.rows) ? event.rows : [],
				raw,
			});
			return;
		}

		if (event.kind === 'insert' || event.kind === 'update' || event.kind === 'delete') {
			this.emit({
				type: event.kind,
				table: this.table,
				pk: event.pk == null ? undefined : String(event.pk),
				new: event.row ?? null,
				old: event.previous ?? null,
				changed: Array.isArray(event.changed) ? event.changed : undefined,
				raw,
			});
		}
	}

	private emit(event: LuxProjectLiveEvent<T>): void {
		for (const handler of this.handlers[event.type]) handler(event);
		if (event.type !== 'snapshot' && event.type !== 'error') {
			for (const handler of this.handlers.change) handler(event);
		}
		// Feed `for await` consumers the data events (errors end the stream via close()).
		if (event.type !== 'error') this.pushIterator(event);
	}

	private pushIterator(event: LuxProjectLiveEvent<T>): void {
		if (this.closed) return;
		const waiter = this.waiters.shift();
		if (waiter) waiter({ value: event, done: false });
		else this.queue.push(event);
	}
}

export class LuxProjectInsertBuilder<TResult> extends LuxProjectThenable<TResult> {
	constructor(
		private client: LuxProjectClient<any>,
		private tableName: string,
		private rowOrRows: Record<string, QueryValue> | Array<Record<string, QueryValue>>,
		private writeOptions?: { upsert?: boolean; onConflict?: string; ttl?: number },
	) {
		super();
	}

	async execute(): Promise<LuxResult<TResult>> {
		// One request for both shapes: an array body inserts all rows server-side
		// in a single round-trip. The server returns the affected row(s)
		// ({result: row} for a single row, {result: [rows]} for an array).
		let path = `/tables/${encodeURIComponent(this.tableName)}`;
		const params = new URLSearchParams();
		if (this.writeOptions?.upsert) {
			if (this.writeOptions.onConflict) params.set('on_conflict', this.writeOptions.onConflict);
			else params.set('upsert', 'true');
		}
		// `ttl` seconds: a row that auto-expires; `0` clears any existing TTL.
		if (this.writeOptions?.ttl != null) params.set('ttl', String(this.writeOptions.ttl));
		const query = params.toString();
		if (query) path += `?${query}`;
		const res = await this.client.request('POST', path, this.rowOrRows);
		if (res.error) return res as LuxResult<TResult>;
		return ok(unwrapResult<TResult>(res.data) as TResult);
	}
}

export class LuxProjectMutationBuilder<TResult> extends LuxProjectFilterBuilder<TResult, LuxProjectMutationBuilder<TResult>> {
	constructor(
		client: LuxProjectClient<any>,
		tableName: string,
		private method: 'PATCH' | 'DELETE',
		private body?: Record<string, QueryValue>,
	) {
		super(client, tableName);
	}

	async execute(): Promise<LuxResult<TResult>> {
		if (this.filters.length === 0) {
			return err(
				'MISSING_FILTER',
				`${this.method === 'PATCH' ? 'update' : 'delete'}() requires at least one filter`,
			);
		}

		const params = this.filteredQueryParams();
		const query = params.toString();
		// Update/delete return the affected rows ({result: [rows]}); unwrap them.
		const res = await this.client.request(
			this.method,
			`/tables/${encodeURIComponent(this.tableName)}${query ? `?${query}` : ''}`,
			this.body,
		);
		if (res.error) return res as LuxResult<TResult>;
		return ok(unwrapResult<TResult>(res.data) as TResult);
	}
}

function unwrapRows<T>(payload: unknown): T[] {
	if (Array.isArray(payload)) return payload as T[];
	if (payload && typeof payload === 'object' && Array.isArray((payload as any).result)) {
		return (payload as any).result as T[];
	}
	return [];
}

function unwrapResult<T>(payload: unknown): T | undefined {
	if (payload && typeof payload === 'object' && 'result' in payload) {
		return (payload as any).result as T;
	}
	return payload as T;
}

function filtersToWhere(filters: QueryFilter[]): string {
	return filters.map((filter) => {
		const op = filterOperatorToWhere(filter.operator);
		if (filter.operator === 'in' || filter.operator === 'notIn') {
			const values = Array.isArray(filter.value) ? filter.value : [filter.value];
			return `${filter.column} ${op} ( ${values.map(formatWhereValue).join(' ')} )`;
		}
		if (
			filter.operator === 'isValid' ||
			filter.operator === 'isNotValid' ||
			filter.operator === 'isNull' ||
			filter.operator === 'isNotNull'
		) {
			return `${filter.column} ${op}`;
		}
		return `${filter.column} ${op} ${formatWhereValue(filter.value as QueryValue)}`;
	}).join(' AND ');
}

function havingToWhere(filters: QueryHaving[]): string {
	return filters.map((filter) => {
		const op = filterOperatorToWhere(filter.operator);
		return `${filter.column} ${op} ${formatWhereValue(filter.value)}`;
	}).join(' AND ');
}

function filterOperatorToWhere(operator: FilterOperator): string {
	switch (operator) {
		case 'eq':
		case 'is':
			return '=';
		case 'neq':
			return '!=';
		case 'gt':
			return '>';
		case 'gte':
			return '>=';
		case 'lt':
			return '<';
		case 'lte':
			return '<=';
		case 'in':
			return 'IN';
		case 'notIn':
			return 'NOT IN';
		case 'isValid':
			return 'IS VALID';
		case 'isNotValid':
			return 'IS NOT VALID';
		case 'isNull':
			return 'IS NULL';
		case 'isNotNull':
			return 'IS NOT NULL';
		case 'contains':
			return 'CONTAINS';
	}
}

function formatWhereValue(value: QueryValue): string {
	if (value === null) return '';
	if (typeof value === 'number' || typeof value === 'boolean') return String(value);
	const str = String(value);
	// Only quote values that would otherwise be split by the engine's WHERE
	// tokenizer (whitespace), or that start with a quote (which the tokenizer
	// would treat as an opening quote). Everything else stays bare, so simple
	// values keep working against engines that predate quoted-WHERE support.
	if (!/\s/.test(str) && !str.startsWith("'")) return str;
	const escaped = str.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
	return `'${escaped}'`;
}

export function createProjectClient<DB extends Record<string, object> = LuxSchema>(
	options: LuxProjectOptions
): LuxProjectClient<DB> {
	return new LuxProjectClient<DB>(options);
}

export function createClient<DB extends Record<string, object> = LuxSchema>(
	url: string,
	key: string,
	options: Omit<LuxProjectOptions, 'url' | 'key'> = {}
): LuxProjectClient<DB> {
	return new LuxProjectClient<DB>({ ...options, url, key });
}

function resolveFetch(fetchImpl?: typeof fetch): typeof fetch {
	const candidate = fetchImpl ?? globalThis.fetch;
	if (!candidate) {
		throw new Error('Lux project client requires a fetch implementation');
	}
	if (typeof globalThis !== 'undefined' && candidate === globalThis.fetch) {
		return candidate.bind(globalThis) as typeof fetch;
	}
	return candidate;
}

function resolveWebSocket(websocketImpl?: typeof WebSocket): typeof WebSocket {
	const candidate = websocketImpl ?? globalThis.WebSocket;
	if (!candidate) {
		throw new Error('Lux project live subscriptions require a WebSocket implementation');
	}
	return candidate;
}
