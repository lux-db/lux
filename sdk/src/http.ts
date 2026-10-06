export interface LuxRequestOptions {
	/** Deadline for response headers and body, in milliseconds. Defaults to 30 seconds. */
	requestTimeoutMs?: number;
	/** Cancels requests owned by this client. An aborted client must not be reused. */
	signal?: AbortSignal;
}

export function requestTimeout(value = 30_000): number {
	if (!Number.isInteger(value) || value < 1 || value > 2_147_483_647) {
		throw new RangeError('requestTimeoutMs must be an integer between 1 and 2147483647');
	}
	return value;
}

/** The deadline includes body consumption, not just the arrival of headers. */
export async function fetchText(
	fetchImpl: typeof fetch,
	url: string,
	init: RequestInit,
	timeoutMs: number,
	clientSignal?: AbortSignal,
): Promise<{ response: Response; text: string }> {
	const controller = new AbortController();
	const parents = [...new Set([init.signal, clientSignal].filter((signal): signal is AbortSignal => signal != null))];
	let rejectAbort: (reason: unknown) => void = () => {};
	const aborted = new Promise<never>((_, reject) => { rejectAbort = reject; });
	const abort = (code: string, message: string) => {
		const error = Object.assign(new Error(message), { code });
		controller.abort(error);
		rejectAbort(error);
	};
	const onAbort = () => abort('LUX_REQUEST_ABORTED', 'Lux request was cancelled');
	const timer = setTimeout(() => abort('LUX_REQUEST_TIMEOUT', 'Lux request deadline exceeded'), timeoutMs);
	for (const parent of parents) parent.addEventListener('abort', onAbort, { once: true });
	if (parents.some(parent => parent.aborted)) onAbort();
	try {
		return await Promise.race([
			aborted,
			(async () => {
				if (controller.signal.aborted) throw controller.signal.reason;
				const response = await fetchImpl(url, { ...init, signal: controller.signal });
				return { response, text: await response.text() };
			})(),
		]);
	} finally {
		clearTimeout(timer);
		for (const parent of parents) parent.removeEventListener('abort', onAbort);
	}
}
