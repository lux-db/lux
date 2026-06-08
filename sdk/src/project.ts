import { LuxAuthClient, type LuxAuthOptions } from './auth';
import type { LuxResult } from './types';
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
type FilterOperator = 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'is';

interface QueryFilter {
	column: string;
	operator: FilterOperator;
	value: QueryValue;
}

interface QueryOrder {
	column: string;
	ascending: boolean;
}

interface QueryNear {
	field: string;
	vector: number[];
	k: number;
	threshold?: number;
}

export type LuxProjectLiveEventType = 'snapshot' | 'insert' | 'update' | 'delete' | 'error';

export interface LuxProjectLiveEvent<T extends Record<string, unknown> = Record<string, unknown>> {
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

type LiveEventHandler<T extends Record<string, unknown>> = (event: LuxProjectLiveEvent<T>) => void;

interface LiveSubscriptionRecord {
	id: string;
	spec: Record<string, unknown>;
	handler: (event: unknown) => void;
	error: (error: { code?: string; message?: string }) => void;
}

export class LuxProjectClient {
	readonly url: string;
	readonly key: string;
	readonly auth: LuxAuthClient;
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
	}

	table<T extends Record<string, unknown> = Record<string, unknown>>(name: string): LuxProjectTable<T> {
		return new LuxProjectTable<T>(this, name);
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

export class LuxProjectTable<T extends Record<string, unknown>> {
	constructor(private client: LuxProjectClient, private name: string) {}

	select(columns = '*'): LuxProjectSelectBuilder<T, T[]> {
		return new LuxProjectSelectBuilder<T, T[]>(this.client, this.name, columns);
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

	live(): LuxProjectLiveSubscription<T> {
		return this.select().live();
	}

	insert(row: Partial<T> & Record<string, QueryValue>): LuxProjectInsertBuilder<unknown>;
	insert(rows: Array<Partial<T> & Record<string, QueryValue>>): LuxProjectInsertBuilder<unknown[]>;
	insert(
		rowOrRows: (Partial<T> & Record<string, QueryValue>) | Array<Partial<T> & Record<string, QueryValue>>,
	): LuxProjectInsertBuilder<unknown | unknown[]> {
		return new LuxProjectInsertBuilder(this.client, this.name, rowOrRows);
	}

	update(patch: Partial<T> & Record<string, QueryValue>): LuxProjectMutationBuilder<unknown> {
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
	protected nearQuery?: QueryNear;
	protected limitCount?: number;
	protected offsetCount?: number;

	protected constructor(
		protected client: LuxProjectClient,
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
		return this.addFilter(column, 'is', value);
	}

	protected addFilter(column: string, operator: FilterOperator, value: QueryValue): TSelf {
		this.filters.push({ column, operator, value });
		return this as unknown as TSelf;
	}

	protected filteredQueryParams(): URLSearchParams {
		const params = new URLSearchParams();
		if (this.filters.length) params.set('where', filtersToWhere(this.filters));
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

export class LuxProjectSelectBuilder<T extends Record<string, unknown>, TResult> extends LuxProjectFilterBuilder<TResult, LuxProjectSelectBuilder<T, TResult>> {
	private expectSingle = false;

	constructor(
		client: LuxProjectClient,
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

	single(): LuxProjectSelectBuilder<T, T> {
		this.expectSingle = true;
		if (this.limitCount == null) this.limitCount = 1;
		return this as unknown as LuxProjectSelectBuilder<T, T>;
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

	live(): LuxProjectLiveSubscription<T> {
		return new LuxProjectLiveSubscription<T>(
			this.client,
			this.tableName,
			this.columns,
			this.filters,
			this.nearQuery,
			this.orderBy,
			this.limitCount,
			this.offsetCount,
		);
	}
}

export class LuxProjectLiveSubscription<T extends Record<string, unknown>> {
	private handlers: Record<LuxProjectLiveEventType | 'change', Array<LiveEventHandler<T>>> = {
		snapshot: [],
		insert: [],
		update: [],
		delete: [],
		error: [],
		change: [],
	};
	private unsubscribeFn: (() => void) | null = null;

	constructor(
		private client: LuxProjectClient,
		private table: string,
		private columns: string,
		private filters: QueryFilter[],
		private nearQuery?: QueryNear,
		private orderBy?: QueryOrder,
		private limitCount?: number,
		private offsetCount?: number,
	) {
		void this.start();
	}

	on(type: LuxProjectLiveEventType | 'change', handler: LiveEventHandler<T>): this {
		this.handlers[type].push(handler);
		return this;
	}

	async unsubscribe(): Promise<void> {
		this.unsubscribeFn?.();
		this.unsubscribeFn = null;
	}

	private async start(): Promise<void> {
		this.unsubscribeFn = await this.client._subscribeLive(
			this.spec(),
			(event) => this.handleEvent(event),
			(error) => this.emit({
				type: 'error',
				table: this.table,
				new: null,
				old: null,
				error,
			}),
		);
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
	}
}

export class LuxProjectInsertBuilder<TResult> extends LuxProjectThenable<TResult> {
	constructor(
		private client: LuxProjectClient,
		private tableName: string,
		private rowOrRows: Record<string, QueryValue> | Array<Record<string, QueryValue>>,
	) {
		super();
	}

	async execute(): Promise<LuxResult<TResult>> {
		if (!Array.isArray(this.rowOrRows)) {
			return this.client.request('POST', `/tables/${encodeURIComponent(this.tableName)}`, this.rowOrRows) as Promise<LuxResult<TResult>>;
		}

		const results: unknown[] = [];
		for (const row of this.rowOrRows) {
			const result = await this.client.request('POST', `/tables/${encodeURIComponent(this.tableName)}`, row);
			if (result.error) return result as LuxResult<TResult>;
			results.push(result.data);
		}
		return ok(results as TResult);
	}
}

export class LuxProjectMutationBuilder<TResult> extends LuxProjectFilterBuilder<TResult, LuxProjectMutationBuilder<TResult>> {
	constructor(
		client: LuxProjectClient,
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
		return this.client.request(
			this.method,
			`/tables/${encodeURIComponent(this.tableName)}${query ? `?${query}` : ''}`,
			this.body,
		) as Promise<LuxResult<TResult>>;
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

function normalizeWhere(where: string): string {
	return where.trim().replace(/\s*(>=|<=|!=|=|>|<)\s*/g, ' $1 ');
}

function filtersToWhere(filters: QueryFilter[]): string {
	return filters.map((filter) => {
		const op = filterOperatorToWhere(filter.operator);
		return normalizeWhere(`${filter.column} ${op} ${formatWhereValue(filter.value)}`);
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
	}
}

function formatWhereValue(value: QueryValue): string {
	if (value === null) return '';
	return String(value);
}

export function createProjectClient(options: LuxProjectOptions): LuxProjectClient {
	return new LuxProjectClient(options);
}

export function createClient(url: string, key: string, options: Omit<LuxProjectOptions, 'url' | 'key'> = {}): LuxProjectClient {
	return new LuxProjectClient({ ...options, url, key });
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
