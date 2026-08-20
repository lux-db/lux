import Lux, { type TSMRangeOptions, type TSRangeOptions } from '../src';

const rangeOptions: TSRangeOptions = {
	aggregation: { type: 'avg', bucketSize: 1_000 },
	count: 1,
};

const mrangeOptions: TSMRangeOptions = {
	aggregation: { type: 'avg', bucketSize: 1_000 },
};

declare const client: Lux;
void client.tsrange('cpu', '-', '+', rangeOptions);
void client.tsmrange('-', '+', 'host=web', mrangeOptions);
void client.timeseries.mrange('-', '+', 'host=web', mrangeOptions);

// @ts-expect-error TSMRANGE does not accept COUNT.
void client.tsmrange('-', '+', 'host=web', { count: 1 });

// @ts-expect-error TimeSeriesNamespace.mrange does not accept COUNT.
void client.timeseries.mrange('-', '+', 'host=web', { count: 1 });
