import type { LuxProjectClient } from './project';
import type { LuxError, LuxResult } from './types';
import { err, ok, toLuxError } from './utils';

export interface LuxStorageObject {
	id: string;
	instance_id: string;
	bucket_id: string;
	path: string;
	size: number;
	type: string | null;
	etag: string | null;
	owner_id: string | null;
	meta: Record<string, unknown>;
	url: string | null;
	created_at: string;
	updated_at: string;
	deleted_at: string | null;
}

export interface LuxStorageUploadOptions {
	contentType?: string;
	upsert?: boolean;
	metadata?: Record<string, unknown>;
	ttl?: number;
}

export interface LuxStorageListOptions {
	prefix?: string;
	limit?: number;
}

export interface LuxStorageSignOptions {
	ttl?: number;
}

type UploadBody = Blob | ArrayBuffer | Uint8Array | Buffer | string;

export class LuxStorageNamespace {
	constructor(private client: LuxProjectClient) {}

	bucket(name: string): LuxStorageBucketClient {
		return new LuxStorageBucketClient(this.client, name);
	}
}

export class LuxStorageBucketClient {
	constructor(
		private client: LuxProjectClient,
		readonly name: string,
	) {}

	async upload(path: string, body: UploadBody, options: LuxStorageUploadOptions = {}): Promise<LuxResult<LuxStorageObject>> {
		try {
			const sign = unwrap<{ url: string; expires_in: number }>(
				await this.client.request('POST', `/storage/object/upload/sign/${encodeURIComponent(this.name)}/${encodePath(path)}`, {
					type: options.contentType,
					upsert: options.upsert ?? false,
					ttl: options.ttl,
					meta: options.metadata,
				}),
			);
			if (sign.error || !sign.data) {
				return { data: null, error: sign.error } as LuxResult<LuxStorageObject>;
			}

			const headers: Record<string, string> = {};
			if (options.contentType) headers['Content-Type'] = options.contentType;
			const put = await this.client.fetchRaw(sign.data.url, {
				method: 'PUT',
				headers,
				body: body as BodyInit,
			});
			if (!put.ok) {
				return err('LUX_STORAGE_UPLOAD_ERROR', `Storage upload failed with HTTP ${put.status}`, {
					status: put.status,
					body: await put.text().catch(() => ''),
				});
			}

			return unwrap(
				await this.client.request('POST', `/storage/object/upload/complete/${encodeURIComponent(this.name)}/${encodePath(path)}`, {
					type: options.contentType,
					upsert: options.upsert ?? false,
					meta: options.metadata,
				}),
			);
		} catch (error) {
			return err('LUX_STORAGE_UPLOAD_ERROR', 'Storage upload failed', toLuxError(error));
		}
	}

	async list(options: LuxStorageListOptions | string = {}): Promise<LuxResult<LuxStorageObject[]>> {
		const opts = typeof options === 'string' ? { prefix: options } : options;
		const params = new URLSearchParams();
		if (opts.prefix) params.set('prefix', opts.prefix);
		if (opts.limit != null) params.set('limit', String(opts.limit));
		const query = params.toString();
		return unwrap(
			await this.client.request('GET', `/storage/object/list/${encodeURIComponent(this.name)}${query ? `?${query}` : ''}`),
		);
	}

	async info(path: string): Promise<LuxResult<LuxStorageObject>> {
		return unwrap(await this.client.request('GET', `/storage/object/info/${encodeURIComponent(this.name)}/${encodePath(path)}`));
	}

	async url(path: string): Promise<LuxResult<{ url: string }>> {
		return unwrap(await this.client.request('GET', `/storage/object/url/${encodeURIComponent(this.name)}/${encodePath(path)}`));
	}

	async sign(path: string, options: LuxStorageSignOptions = {}): Promise<LuxResult<{ url: string; expires_in: number }>> {
		return unwrap(
			await this.client.request('POST', `/storage/object/sign/${encodeURIComponent(this.name)}/${encodePath(path)}`, {
				ttl: options.ttl,
			}),
		);
	}

	async download(path: string): Promise<LuxResult<Blob>> {
		try {
			const signed = await this.sign(path);
			if (signed.error || !signed.data) {
				return { data: null, error: signed.error } as LuxResult<Blob>;
			}
			const response = await this.client.fetchRaw(signed.data.url);
			if (!response.ok) {
				return err('LUX_STORAGE_DOWNLOAD_ERROR', `Storage download failed with HTTP ${response.status}`, {
					status: response.status,
				});
			}
			return ok(await response.blob());
		} catch (error) {
			return err('LUX_STORAGE_DOWNLOAD_ERROR', 'Storage download failed', toLuxError(error));
		}
	}

	async remove(path: string): Promise<LuxResult<null>> {
		return unwrap(await this.client.request('DELETE', `/storage/object/${encodeURIComponent(this.name)}/${encodePath(path)}`));
	}
}

function unwrap<T>(result: LuxResult<any>): LuxResult<T> {
	if (result.error) return { data: null, error: result.error };
	const data = result.data && typeof result.data === 'object' && 'data' in result.data ? result.data.data : result.data;
	return ok(data as T);
}

function encodePath(path: string): string {
	return path
		.replace(/^\/+/, '')
		.split('/')
		.map(encodeURIComponent)
		.join('/');
}
