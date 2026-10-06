import assert from "node:assert/strict";
import { Queue, QueueEvents, Worker } from "bullmq";

const port = Number(process.env.LUX_COMPAT_PORT ?? "26379");
const password = process.env.LUX_COMPAT_PASSWORD ?? "lux-client-compat";
const connection = {
  host: "127.0.0.1",
  port,
  password,
  protocol: 2,
  maxRetriesPerRequest: null,
};
const queueName = `lux-compat-${process.pid}`;
const queue = new Queue(queueName, { connection });
queue.setMaxListeners(20);
const events = new QueueEvents(queueName, { connection });
const attempts = new Map<string, number>();
const worker = new Worker(
  queueName,
  async job => {
    attempts.set(job.id ?? "", (attempts.get(job.id ?? "") ?? 0) + 1);
    if (job.name === "retry" && job.attemptsMade === 0) throw new Error("expected first-attempt failure");
    return { id: job.id, value: job.data.value };
  },
  { connection, concurrency: 4 },
);

try {
  await Promise.all([queue.waitUntilReady(), events.waitUntilReady(), worker.waitUntilReady()]);
  const jobs = await Promise.all([
    ...Array.from({ length: 12 }, (_, index) => queue.add("immediate", { value: `job-${index}` })),
    queue.add("delayed", { value: "later" }, { delay: 100 }),
    queue.add("retry", { value: "retried" }, { attempts: 2, backoff: { type: "fixed", delay: 25 } }),
  ]);
  const results = await Promise.all(jobs.map(job => job.waitUntilFinished(events, 15_000)));
  assert.equal(results.length, 14);
  assert.equal(new Set(results.map(result => result.id)).size, 14);
  const retry = jobs.at(-1);
  assert.equal(attempts.get(retry?.id ?? ""), 2);

  const counts = await queue.getJobCounts("waiting", "active", "delayed", "completed", "failed");
  assert.equal(counts.waiting, 0);
  assert.equal(counts.active, 0);
  assert.equal(counts.delayed, 0);
  assert.equal(counts.failed, 0);
  assert.equal(counts.completed, 14);
  console.log("client: BullMQ 6.3.4 (workers, concurrency, delayed jobs, retries, events)");
} finally {
  await Promise.allSettled([worker.close(), events.close(), queue.close()]);
}
