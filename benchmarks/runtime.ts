import { BENCHMARK_PASSWORD } from "./config";

export function progress(message: string): void {
  if (process.stdout.isTTY) process.stdout.write(`${message}\n`);
}

export async function command(
  args: string[],
  options: { allowFailure?: boolean; quiet?: boolean; timeoutMs?: number } = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const child = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const timer = setTimeout(() => child.kill("SIGKILL"), options.timeoutMs ?? 180_000);
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  clearTimeout(timer);
  if (!options.quiet && stderr.trim()) process.stderr.write(stderr);
  if (exitCode !== 0 && !options.allowFailure)
    throw new Error(`${args.join(" ")} exited ${exitCode}\n${stdout}${stderr}`);
  return { stdout, stderr, exitCode };
}

export async function docker(...args: string[]): Promise<string> {
  return (await command(["docker", ...args])).stdout.trim();
}

export async function imageInventory(image: string): Promise<Record<string, unknown>> {
  const inspected = JSON.parse(await docker("image", "inspect", image))[0];
  return {
    requested: image,
    id: inspected.Id,
    repo_digests: inspected.RepoDigests ?? [],
    architecture: inspected.Architecture,
    os: inspected.Os,
    labels: inspected.Config?.Labels ?? {},
  };
}

export async function waitReady(
  network: string,
  alias: string,
  clientImage: string,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const result = await command(
      [
        "docker", "run", "--rm", "--network", network, clientImage,
        "redis-cli", "-h", alias, "-a", BENCHMARK_PASSWORD, "PING",
      ],
      { allowFailure: true, quiet: true, timeoutMs: 5_000 },
    );
    if (result.exitCode === 0 && result.stdout.includes("PONG")) return;
    await Bun.sleep(50);
  }
  throw new Error(`${alias} did not become ready`);
}

export async function publishedPort(container: string, containerPort = 6379): Promise<number> {
  const output = await docker("port", container, `${containerPort}/tcp`);
  const port = Number(output.match(/:(\d+)$/)?.[1]);
  if (!Number.isInteger(port) || port <= 0)
    throw new Error(`invalid published port: ${output}`);
  return port;
}
