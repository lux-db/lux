import type { LuxError, LuxResult } from './types';

/** Keep browser and server session names identical without sharing projects. */
export function projectStorageKey(url: string | undefined, prefix: string): string {
	return url ? `${prefix}-${encodeURIComponent(url.replace(/\/+$/, ''))}` : prefix;
}

export function ok<T>(data: T): LuxResult<T> {
	return { data, error: null };
}

export function err<T>(code: string, message: string, details?: unknown): LuxResult<T> {
	return { data: null, error: { code, message, details } };
}

export function toLuxError(error: unknown, fallbackCode = 'LUX_SDK_ERROR'): LuxError {
	if (typeof error === 'object' && error && 'message' in error) {
		const code = 'code' in error && typeof error.code === 'string' ? error.code : fallbackCode;
		return { code, message: String((error as { message: unknown }).message), details: error };
	}
	return { code: fallbackCode, message: String(error) };
}
