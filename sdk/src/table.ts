import type {
	KSubEvent,
	LuxError,
	LuxResult,
	TableChangeEvent,
	TableChangeType,
	TableErrorEvent,
	TableRow,
	TableSchema,
} from './types';
import { err, ok, toLuxError } from './utils';

type TableWhereOp =
	| '='
	| '!='
	| '>'
	| '<'
	| '>='
	| '<='
	| 'LIKE'
	| 'ILIKE'
	| 'IN'
	| 'NOT IN'
	| 'IS VALID'
	| 'IS NOT VALID'
	| 'CONTAINS';
type TableWhereValue = string | number | boolean;

interface TableWhereCondition {
	field: string;
	op: TableWhereOp;
	value: TableWhereValue | TableWhereValue[];
}

/** Serialize a field value: JSON objects/arrays round-trip as JSON text. */
function serializeFieldValue(v: unknown): string {
	if (v !== null && typeof v === 'object') {
		return JSON.stringify(v);
	}
	return String(v);
}

/** Serialize one WHERE condition into RESP tokens. */
function serializeCondition(cond: TableWhereCondition): string[] {
	if (cond.op === 'IN' || cond.op === 'NOT IN') {
		const values = Array.isArray(cond.value) ? cond.value : [cond.value];
		return [
			cond.field,
			...(cond.op === 'NOT IN' ? ['NOT', 'IN'] : ['IN']),
			'(',
			...values.map(String),
			')',
		];
	}
	if (cond.op === 'IS VALID') return [cond.field, 'IS', 'VALID'];
	if (cond.op === 'IS NOT VALID') return [cond.field, 'IS', 'NOT', 'VALID'];
	return [cond.field, cond.op, String(cond.value)];
}

/** Join serialized conditions with AND separators. */
function serializeConditions(conditions: TableWhereCondition[]): string[] {
	const out: string[] = [];
	for (let i = 0; i < conditions.length; i++) {
		out.push(...serializeCondition(conditions[i]));
		if (i < conditions.length - 1) out.push('AND');
	}
	return out;
}

interface TableJoinClause {
	type: 'INNER' | 'LEFT';
	table: string;
	alias: string;
	onLeft: string;
	onRight: string;
}

interface TableSimilarityClause {
	field: string;
	vector: number[];
	k: number;
	threshold?: number;
}

interface TableHavingCondition {
	field: string;
	op: TableWhereOp;
	value: TableWhereValue;
}

interface TableClient {
	call(command: string, ...args: Array<string | number>): Promise<unknown>;
	_tselect(args: string[]): Promise<TableRow[]>;
	_subscribePattern(pattern: string, handler: (event: KSubEvent) => void): Promise<() => void>;
}

export interface TableQueryBuilderOptions<T extends object> {
	schema?: TableSchema<T>;
}

export class TableSubscription<T extends object> {
	private client: TableClient;
	private table: string;
	private selectArgsBuilder: (extra?: TableWhereCondition[]) => string[];
	private handlers: {
		change: Array<(event: TableChangeEvent<T>) => void>;
		insert: Array<(event: TableChangeEvent<T>) => void>;
		update: Array<(event: TableChangeEvent<T>) => void>;
		delete: Array<(event: TableChangeEvent<T>) => void>;
		error: Array<(event: TableErrorEvent) => void>;
	} = {
		change: [],
		insert: [],
		update: [],
		delete: [],
		error: [],
	};
	private knownRows = new Map<string, T>();
	private unsubscribeFn: (() => void) | null = null;
	private initError: LuxError | null;

	constructor(
		client: TableClient,
		table: string,
		selectArgsBuilder: (extra?: TableWhereCondition[]) => string[],
		initError: LuxError | null = null,
	) {
		this.client = client;
		this.table = table;
		this.selectArgsBuilder = selectArgsBuilder;
		this.initError = initError;
		void this.start();
	}

	on(event: 'insert' | 'update' | 'delete' | 'change', handler: (event: TableChangeEvent<T>) => void): this;
	on(event: 'error', handler: (event: TableErrorEvent) => void): this;
	on(
		event: TableChangeType,
		handler: ((event: TableChangeEvent<T>) => void) | ((event: TableErrorEvent) => void),
	): this {
		(this.handlers[event] as Array<typeof handler>).push(handler);
		return this;
	}

	async unsubscribe(): Promise<void> {
		if (this.unsubscribeFn) {
			this.unsubscribeFn();
			this.unsubscribeFn = null;
		}
	}

	private emitError(error: LuxError): void {
		for (const handler of this.handlers.error) {
			handler({ type: 'error', table: this.table, error });
		}
	}

	private emitChange(event: TableChangeEvent<T>): void {
		for (const handler of this.handlers.change) handler(event);
		for (const handler of this.handlers[event.type]) handler(event);
	}

	private extractPkFromKey(key: string): string | null {
		const prefix = `_t:${this.table}:row:`;
		if (!key.startsWith(prefix)) return null;
		return key.slice(prefix.length);
	}

	private async fetchMatches(extra?: TableWhereCondition[]): Promise<T[]> {
		const args = this.selectArgsBuilder(extra);
		const rows = await this.client._tselect(args);
		return rows as T[];
	}

	private async start(): Promise<void> {
		if (this.initError) {
			this.emitError(this.initError);
			return;
		}

		try {
			const initial = await this.fetchMatches();
			for (const row of initial) {
				const id = (row as { id?: number | string }).id;
				if (id == null) continue;
				this.knownRows.set(String(id), row);
			}

			const pattern = `_t:${this.table}:row:*`;
			this.unsubscribeFn = await this.client._subscribePattern(pattern, (raw) => {
				void this.handleRawChange(raw);
			});
		} catch (error) {
			this.emitError(toLuxError(error, 'LUX_SUBSCRIBE_INIT_ERROR'));
		}
	}

	private async handleRawChange(raw: KSubEvent): Promise<void> {
		const pk = this.extractPkFromKey(raw.key);
		if (!pk) return;

		try {
			const previous = this.knownRows.get(pk) ?? null;
			const rows = await this.fetchMatches([{ field: 'id', op: '=', value: pk }]);
			const next = rows[0] ?? null;

			if (!previous && !next) return;

			if (!previous && next) {
				this.knownRows.set(pk, next);
				this.emitChange({
					type: 'insert',
					table: this.table,
					pk,
					operation: raw.operation,
					new: next,
					old: null,
					raw,
				});
				return;
			}

			if (previous && !next) {
				this.knownRows.delete(pk);
				this.emitChange({
					type: 'delete',
					table: this.table,
					pk,
					operation: raw.operation,
					new: null,
					old: previous,
					raw,
				});
				return;
			}

			if (!previous || !next) return;

			this.knownRows.set(pk, next);
			const previousRow = previous as Record<string, unknown>;
			const nextRow = next as Record<string, unknown>;
			const changed = Object.keys(nextRow).filter((key) => previousRow[key] !== nextRow[key]);
			this.emitChange({
				type: 'update',
				table: this.table,
				pk,
				operation: raw.operation,
				new: next,
				old: previous,
				changed,
				raw,
			});
		} catch (error) {
			this.emitError(toLuxError(error, 'LUX_SUBSCRIBE_EVENT_ERROR'));
		}
	}
}

export class TableQueryBuilder<T extends object = TableRow> {
	private client: TableClient;
	private name: string;
	private conditions: TableWhereCondition[] = [];
	private orderField?: string;
	private orderDir?: 'ASC' | 'DESC';
	private limitCount?: number;
	private offsetCount?: number;
	private joinClause?: TableJoinClause;
	private similarityClause?: TableSimilarityClause;
	private groupFields: string[] = [];
	private havingConditions: TableHavingCondition[] = [];
	private selectClause = '*';
	private expectSingle = false;
	private allowEmptySingle = false;
	private schema?: TableSchema<T>;

	constructor(client: TableClient, name: string, options?: TableQueryBuilderOptions<T>) {
		this.client = client;
		this.name = name;
		this.schema = options?.schema;
	}

	private validateRow(row: TableRow): T {
		if (!this.schema) return row as T;
		if (this.schema.safeParse) {
			const parsed = this.schema.safeParse(row);
			if (!parsed.success) {
				throw new Error('row failed schema validation');
			}
			return parsed.data;
		}
		if (this.schema.parse) {
			return this.schema.parse(row);
		}
		return row as T;
	}

	private buildSelectArgs(extra?: TableWhereCondition[]): string[] {
		const args: string[] = [this.selectClause, 'FROM', this.name];
		const allConditions = extra ? [...this.conditions, ...extra] : this.conditions;

		if (this.joinClause) {
			args.push(
				...(this.joinClause.type === 'LEFT' ? ['LEFT', 'JOIN'] : ['JOIN']),
				this.joinClause.table,
				this.joinClause.alias,
				'ON',
				this.joinClause.onLeft,
				'=',
				this.joinClause.onRight,
			);
		}

		if (allConditions.length) {
			args.push('WHERE', ...serializeConditions(allConditions));
		}

		if (this.groupFields.length) {
			args.push('GROUP', 'BY', ...this.groupFields);
		}

		if (this.havingConditions.length) {
			args.push('HAVING');
			for (let i = 0; i < this.havingConditions.length; i++) {
				const cond = this.havingConditions[i];
				args.push(cond.field, cond.op, String(cond.value));
				if (i < this.havingConditions.length - 1) {
					args.push('AND');
				}
			}
		}

		if (this.similarityClause) {
			args.push(
				'NEAR',
				this.similarityClause.field,
				`[${this.similarityClause.vector.join(',')}]`,
				'K',
				String(this.similarityClause.k),
			);
			if (this.similarityClause.threshold != null) {
				args.push('THRESHOLD', String(this.similarityClause.threshold));
			}
		}

		if (this.orderField) {
			args.push('ORDER', 'BY', this.orderField, this.orderDir || 'ASC');
		}
		if (this.limitCount != null) {
			args.push('LIMIT', String(this.limitCount));
		}
		if (this.offsetCount != null) {
			args.push('OFFSET', String(this.offsetCount));
		}

		return args;
	}

	select(columns = '*'): this {
		this.selectClause = columns;
		return this;
	}

	single(): this {
		this.expectSingle = true;
		this.allowEmptySingle = false;
		if (this.limitCount == null) {
			this.limitCount = 1;
		}
		return this;
	}

	maybeSingle(): this {
		this.expectSingle = true;
		this.allowEmptySingle = true;
		if (this.limitCount == null) {
			this.limitCount = 1;
		}
		return this;
	}

	where(field: string, op: TableWhereOp, value: TableWhereValue): this {
		this.conditions.push({ field, op, value });
		return this;
	}

	eq(field: string, value: TableWhereValue): this {
		return this.where(field, '=', value);
	}

	neq(field: string, value: TableWhereValue): this {
		return this.where(field, '!=', value);
	}

	gt(field: string, value: TableWhereValue): this {
		return this.where(field, '>', value);
	}

	gte(field: string, value: TableWhereValue): this {
		return this.where(field, '>=', value);
	}

	lt(field: string, value: TableWhereValue): this {
		return this.where(field, '<', value);
	}

	lte(field: string, value: TableWhereValue): this {
		return this.where(field, '<=', value);
	}

	like(field: string, value: string): this {
		return this.where(field, 'LIKE', value);
	}

	ilike(field: string, value: string): this {
		return this.where(field, 'ILIKE', value);
	}

	in(field: string, values: TableWhereValue[]): this {
		this.conditions.push({ field, op: 'IN', value: values });
		return this;
	}

	notIn(field: string, values: TableWhereValue[]): this {
		this.conditions.push({ field, op: 'NOT IN', value: values });
		return this;
	}

	/** Match rows where a JSON dot-path resolves to a present, non-null value. */
	isValid(field: string): this {
		this.conditions.push({ field, op: 'IS VALID', value: '' });
		return this;
	}

	/** Match rows where a JSON dot-path is absent or resolves to null. */
	isNotValid(field: string): this {
		this.conditions.push({ field, op: 'IS NOT VALID', value: '' });
		return this;
	}

	/** Match rows where an ARRAY column (or array-valued path) contains a value. */
	contains(field: string, value: TableWhereValue): this {
		this.conditions.push({ field, op: 'CONTAINS', value });
		return this;
	}

	orderBy(field: string, dir: 'asc' | 'desc' = 'asc'): this {
		this.orderField = field;
		this.orderDir = dir.toUpperCase() as 'ASC' | 'DESC';
		return this;
	}

	order(field: string, options: { ascending?: boolean } = {}): this {
		return this.orderBy(field, options.ascending === false ? 'desc' : 'asc');
	}

	limit(n: number): this {
		this.limitCount = n;
		return this;
	}

	offset(n: number): this {
		this.offsetCount = n;
		return this;
	}

	join(table: string, alias: string, onLeft: string, onRight: string): this {
		this.joinClause = { type: 'INNER', table, alias, onLeft, onRight };
		return this;
	}

	leftJoin(table: string, alias: string, onLeft: string, onRight: string): this {
		this.joinClause = { type: 'LEFT', table, alias, onLeft, onRight };
		return this;
	}

	group(fields: string | string[]): this {
		this.groupFields = Array.isArray(fields)
			? fields
			: fields.split(',').map((field) => field.trim()).filter(Boolean);
		return this;
	}

	groupBy(fields: string | string[]): this {
		return this.group(fields);
	}

	having(field: string, op: TableWhereOp, value: TableWhereValue): this {
		this.havingConditions.push({ field, op, value });
		return this;
	}

	near(field: string, vector: number[], options: { k?: number; threshold?: number } = {}): this {
		this.similarityClause = {
			field,
			vector,
			k: options.k ?? 10,
			threshold: options.threshold,
		};
		return this;
	}

	similar(field: string, vector: number[], options: { k?: number; threshold?: number } = {}): this {
		return this.near(field, vector, options);
	}

	async run(): Promise<LuxResult<T[] | T>> {
		try {
			const rows = await this.client._tselect(this.buildSelectArgs());

			const validated = rows.map((row) => this.validateRow(row));

			if (this.expectSingle) {
				if (validated.length === 0) {
					if (this.allowEmptySingle) return ok(null as unknown as T);
					return err('NOT_FOUND', `No rows found in table '${this.name}'`);
				}
				return ok(validated[0]);
			}

			return ok(validated);
		} catch (error) {
			return err('TSELECT_ERROR', `Failed to query table '${this.name}'`, toLuxError(error));
		}
	}

	then<TFulfilled = LuxResult<T[] | T>, TRejected = never>(
		onfulfilled?: ((value: LuxResult<T[] | T>) => TFulfilled | PromiseLike<TFulfilled>) | null,
		onrejected?: ((reason: unknown) => TRejected | PromiseLike<TRejected>) | null,
	): Promise<TFulfilled | TRejected> {
		return this.run().then(onfulfilled, onrejected);
	}

	async insert(data: Record<string, unknown>): Promise<LuxResult<number>> {
		try {
			if (this.schema) {
				this.validateRow(data as TableRow);
			}
			const args: (string | number)[] = [this.name];
			for (const [k, v] of Object.entries(data)) {
				args.push(k, serializeFieldValue(v));
			}
			const result = await this.client.call('TINSERT', ...args) as string;
			return ok(parseInt(result, 10) || 0);
		} catch (error) {
			return err('TINSERT_ERROR', `Failed to insert into '${this.name}'`, toLuxError(error));
		}
	}

	/** Declare a typed index on a JSON dot-path, e.g. ('meta.reactions.count', 'int'). */
	async createIndex(
		path: string,
		type: 'int' | 'float' | 'bool' | 'timestamp' | 'str',
	): Promise<LuxResult<true>> {
		try {
			await this.client.call('TINDEX', this.name, path, type.toUpperCase());
			return ok(true);
		} catch (error) {
			return err('TINDEX_ERROR', `Failed to index '${path}'`, toLuxError(error));
		}
	}

	/** Drop a previously declared JSON path index. */
	async dropIndex(path: string): Promise<LuxResult<true>> {
		try {
			await this.client.call('TDROPINDEX', this.name, path);
			return ok(true);
		} catch (error) {
			return err('TDROPINDEX_ERROR', `Failed to drop index '${path}'`, toLuxError(error));
		}
	}

	async update(id: number | string, data: Record<string, unknown>): Promise<LuxResult<number>>;
	async update(data: Record<string, unknown>): Promise<LuxResult<number>>;
	async update(
		idOrData: number | string | Record<string, unknown>,
		data?: Record<string, unknown>,
	): Promise<LuxResult<number>> {
		try {
			const hasExplicitId = data !== undefined;
			const patch = hasExplicitId ? data : idOrData as Record<string, unknown>;
			if (!hasExplicitId && this.conditions.length === 0) {
				return err('MISSING_WHERE', 'update requires at least one filter');
			}
			const args: (string | number)[] = [this.name, 'SET'];
			for (const [k, v] of Object.entries(patch)) {
				args.push(k, serializeFieldValue(v));
			}
			args.push('WHERE');
			if (hasExplicitId) {
				args.push('id', '=', String(idOrData));
			} else {
				args.push(...serializeConditions(this.conditions));
			}
			const result = await this.client.call('TUPDATE', ...args) as string | number;
			return ok(Number(result) || 0);
		} catch (error) {
			return err('TUPDATE_ERROR', `Failed to update '${this.name}'`, toLuxError(error));
		}
	}

	async delete(...ids: Array<number | string>): Promise<LuxResult<number>> {
		try {
			if (ids.length === 0) {
				if (this.conditions.length === 0) {
					return err('MISSING_WHERE', 'delete requires at least one filter');
				}
				const args: (string | number)[] = ['FROM', this.name, 'WHERE'];
				args.push(...serializeConditions(this.conditions));
				const result = await this.client.call('TDELETE', ...args) as string | number;
				return ok(Number(result) || 0);
			}

			let deleted = 0;
			for (const id of ids) {
				const result = await this.client.call('TDELETE', 'FROM', this.name, 'WHERE', 'id', '=', String(id)) as string | number;
				deleted += Number(result) || 0;
			}
			return ok(deleted);
		} catch (error) {
			return err('TDELETE_ERROR', `Failed to delete from '${this.name}'`, toLuxError(error));
		}
	}

	subscribe(): TableSubscription<T> {
		return new TableSubscription<T>(this.client, this.name, (extra) => this.buildSelectArgs(extra));
	}
}
