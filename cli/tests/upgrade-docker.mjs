#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync, renameSync } from "node:fs";

const args = process.argv.slice(2);
const docker = process.env.UPGRADE_TEST_DOCKER_BINARY;
if (!docker) throw Error("missing test Docker executable");
const marker = process.env.VALIDATION_MARKER;
const mode = process.env.AUTO_TEST_MODE;
if (mode === "verification-write" && args[0] === "exec" && args.at(-1) === "final") {
  const inspected = spawnSync(
    docker,
    ["inspect", "--format", "{{json .Config.Env}}", args[1]],
    { encoding: "utf8" },
  );
  if (inspected.status !== 0) throw Error("fixture could not inspect candidate environment");
  const password = JSON.parse(inspected.stdout)
    .find((value) => value.startsWith("LUX_PASSWORD="))
    ?.slice("LUX_PASSWORD=".length);
  if (!password) throw Error("fixture candidate has no password");
  const script = `
    const s = require("node:net").createConnection({host:"127.0.0.1", port:6379});
    const encode = a => "*"+a.length+"\\r\\n"+a.map(v=>"$"+Buffer.byteLength(v)+"\\r\\n"+v+"\\r\\n").join("");
    let body="";
    s.setTimeout(5000,()=>process.exit(2));
    s.on("error",()=>process.exit(3));
    s.on("connect",()=>s.write(encode(["AUTH",process.env.LUX_PASSWORD])+encode(["SET","verification-only","discard-me"])));
    s.on("data",c=>{body+=c;if(body==="+OK\\r\\n+OK\\r\\n"){s.destroy();process.exit(0);}if(body.includes("-ERR"))process.exit(4);});
  `;
  const injected = spawnSync(docker, [
    "run",
    "--rm",
    "--network",
    `container:${args[1]}`,
    "-e",
    `LUX_PASSWORD=${password}`,
    "--entrypoint",
    "node",
    process.env.UPGRADE_TEST_CLIENT_IMAGE ||
      "node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf",
    "-e",
    script,
  ]);
  if (injected.status !== 0) throw Error("fixture verification write failed");
}
if (mode === "import-failure" && args[0] === "exec" && args.at(-1) === "restore-snapshot") {
  console.error("fixture: candidate import was refused");
  process.exit(79);
}
if (["snapshot-failure", "stopped-snapshot-failure"].includes(mode) && args[0] === "run" && args.at(-1) === "snapshot") {
  console.error("fixture: snapshot was not confirmed");
  process.exit(78);
}
function inspectId(image) {
  const result = spawnSync(
    docker,
    ["image", "inspect", image, "--format", "{{.Id}}"],
    { encoding: "utf8" },
  );
  if (result.status !== 0) process.exit(result.status ?? 1);
  return result.stdout.trim();
}

// Only registry requests use preloaded fixture images. Container operations,
// volumes, snapshots, network changes and readiness checks use real Docker.
if (args[0] === "buildx" && args[1] === "imagetools") {
  console.log(JSON.stringify(inspectId(args[3])));
  process.exit(0);
}
if (args[0] === "pull") {
  if (!args[1].startsWith("ghcr.io/lux-db/lux:local-validation-upgrade-"))
    throw Error("unexpected pull target");
  inspectId(args[1]);
  console.log("fixture: selected preloaded image");
  process.exit(0);
}
if (
  args[0] === "image" &&
  args[1] === "inspect" &&
  args.includes("{{json .RepoDigests}}")
) {
  console.log(JSON.stringify([`fixture@${inspectId(args[2])}`]));
  process.exit(0);
}

if (
  mode === "probe-failure" &&
  args[0] === "run" &&
  args.some((arg) => arg.includes("-verify-"))
) {
  console.error("fixture: candidate start failed");
  process.exit(77);
}
const result = spawnSync(docker, args, { maxBuffer: 16 * 1024 * 1024 });
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
const point =
  mode === "cutover-interruption" &&
  args[0] === "run" &&
  args[args.indexOf("--name") + 1] === process.env.AUTO_CUTOVER_NAME
    ? "run"
    : process.env.VALIDATION_PAUSE;
if (result.status === 0 && point === args[0] && marker && !existsSync(marker)) {
  writeFileSync(`${marker}.tmp`, JSON.stringify({ pid: process.pid, point }));
  renameSync(`${marker}.tmp`, marker);
  // The test stops this exact owned process and its CLI parent at the checkpoint.
  setInterval(() => {}, 1000);
} else process.exit(result.status ?? 1);
