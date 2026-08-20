import type {
	TSAddOptions,
	TSMRangeOptions,
	TSMRangeResult,
	TSRangeOptions,
	TSSample,
	VSearchResult,
} from './types';

interface NamespaceClient {
	call(command: string, ...args: Array<string | number>): Promise<unknown>;
	vget(key: string): Promise<{ dims: number; vector: number[]; metadata?: Record<string, unknown> } | null>;
	vsearch(query: number[], options: { k: number; filter?: { key: string; value: string }; meta?: boolean }): Promise<VSearchResult[]>;
	vcard(): Promise<number>;
	tsadd(key: string, timestamp: number | '*', value: number, options?: TSAddOptions): Promise<number>;
	tsget(key: string): Promise<TSSample | null>;
	tsrange(key: string, from: number | '-', to: number | '+', options?: TSRangeOptions): Promise<TSSample[]>;
	tsmrange(from: number | '-', to: number | '+', filter: string, options?: TSMRangeOptions): Promise<TSMRangeResult[]>;
	tsinfo(key: string): Promise<Record<string, unknown>>;
}

export class VectorNamespace {
	private client: NamespaceClient;

	constructor(client: NamespaceClient) {
		this.client = client;
	}

	async set(key: string, vector: number[], metadata?: Record<string, unknown>): Promise<string> {
		const args: (string | number)[] = [key, vector.length, ...vector];
		if (metadata) {
			args.push('META', JSON.stringify(metadata));
		}
		return this.client.call('VSET', ...args) as Promise<string>;
	}

	async get(key: string): Promise<{ dims: number; vector: number[]; metadata?: Record<string, unknown> } | null> {
		return this.client.vget(key);
	}

	async search(query: number[], options: { topK: number; filter?: { key: string; value: string }; meta?: boolean }): Promise<VSearchResult[]> {
		return this.client.vsearch(query, { k: options.topK, filter: options.filter, meta: options.meta ?? true });
	}

	async count(): Promise<number> {
		return this.client.vcard();
	}
}

export class TimeSeriesNamespace {
	private client: NamespaceClient;

	constructor(client: NamespaceClient) {
		this.client = client;
	}

	async add(key: string, value: number, options?: { timestamp?: number | '*'; retention?: number; labels?: Record<string, string> }): Promise<number> {
		return this.client.tsadd(key, options?.timestamp ?? '*', value, { retention: options?.retention, labels: options?.labels });
	}

	async get(key: string): Promise<TSSample | null> {
		return this.client.tsget(key);
	}

	async range(key: string, from: number | '-', to: number | '+', options?: TSRangeOptions): Promise<TSSample[]> {
		return this.client.tsrange(key, from, to, options);
	}

	async mrange(from: number | '-', to: number | '+', filter: string, options?: TSMRangeOptions): Promise<TSMRangeResult[]> {
		return this.client.tsmrange(from, to, filter, options);
	}

	async info(key: string): Promise<Record<string, unknown>> {
		return this.client.tsinfo(key);
	}
}
