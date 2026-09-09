import { RespConnection } from "./resp";
import { sampleFromLatencies, type Sample } from "./stats";

export async function measureRealtime(
  port: number,
  password: string,
  warmup: number,
  requests: number,
  subscriberCount = 1,
): Promise<Sample> {
  const subscribers = await Promise.all(
    Array.from({ length: subscriberCount }, () => RespConnection.connect(port, password)),
  );
  const writer = await RespConnection.connect(port, password);
  try {
    await Promise.all(
      subscribers.map((subscriber) => subscriber.request(["KSUB", "benchmark:realtime:*"])),
    );
    const run = async (count: number, collect: boolean): Promise<number[]> => {
      const latencies: number[] = [];
      for (let index = 0; index < count; index++) {
        const events = subscribers.map((subscriber) => subscriber.read());
        const started = performance.now();
        await writer.request([
          "SET",
          `benchmark:realtime:${index % 1024}`,
          String(index),
        ]);
        const messages = await Promise.all(events);
        for (const message of messages) {
          if (!Array.isArray(message) || message[0] !== "kmessage")
            throw new Error(`unexpected realtime message: ${JSON.stringify(message)}`);
        }
        if (collect) latencies.push(performance.now() - started);
      }
      return latencies;
    };
    await run(warmup, false);
    const started = performance.now();
    const latencies = await run(requests, true);
    return sampleFromLatencies(latencies, performance.now() - started);
  } finally {
    for (const subscriber of subscribers) subscriber.close();
    writer.close();
  }
}
