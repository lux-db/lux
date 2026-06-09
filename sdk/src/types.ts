export interface VSearchResult {
	key: string;
	similarity: number;
	metadata?: Record<string, unknown>;
}

export interface TSSample {
	timestamp: number;
	value: number;
}

export interface TSAddOptions {
	retention?: number;
	labels?: Record<string, string>;
}

export interface TSRangeOptions {
	aggregation?: {
		type: 'avg' | 'sum' | 'min' | 'max' | 'count' | 'first' | 'last' | 'range' | 'std.p' | 'std.s' | 'var.p' | 'var.s';
		bucketSize: number;
	};
}

export interface TSMRangeResult {
	key: string;
	labels: Record<string, string>;
	samples: TSSample[];
}

export interface KSubEvent {
	pattern: string;
	key: string;
	operation: string;
}

export interface TableRow {
	id?: number | string;
	[field: string]: unknown;
}

export type LuxInferRow<T> = T extends readonly (infer Row)[] ? Row : T;

export type LuxTypedRow<T> = LuxInferRow<T> extends object
	? LuxInferRow<T>
	: TableRow;

export type LuxAggregateValue = number | string;

export type LuxAggregateRow<Aliases extends string = string> = Record<Aliases, LuxAggregateValue>;

export interface LuxSimilarity {
	_similarity: number | string;
}

export type LuxNearRow<T extends object = Record<string, unknown>> = T & LuxSimilarity;

export interface LuxError {
	code: string;
	message: string;
	details?: unknown;
}

export interface LuxResult<T> {
	data: T | null;
	error: LuxError | null;
}

type SchemaSafeParse<T> = { success: true; data: T } | { success: false; error: unknown };

export interface TableSchema<T> {
	parse?: (input: unknown) => T;
	safeParse?: (input: unknown) => SchemaSafeParse<T>;
}

export type TableChangeType = 'insert' | 'update' | 'delete' | 'change' | 'error';

export interface TableChangeEvent<T extends object = TableRow> {
	type: Exclude<TableChangeType, 'error'>;
	table: string;
	pk: string;
	operation: string;
	new: T | null;
	old: T | null;
	changed?: string[];
	raw?: KSubEvent;
}

export interface TableErrorEvent {
	type: 'error';
	table: string;
	error: LuxError;
}
