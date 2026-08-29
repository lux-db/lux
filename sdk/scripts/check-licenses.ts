import { readFileSync } from "node:fs";

const allowed = new Set(["Apache-2.0", "MIT"]);
const lock = readFileSync(new URL("../bun.lock", import.meta.url), "utf8");
const packages = [...lock.matchAll(/^    "([^"]+)": \["/gm)].map((match) => match[1]);

if (packages.length === 0) {
    throw new Error("bun.lock did not contain any dependency packages");
}

const rejected: string[] = [];
for (const name of packages) {
    const manifestPath = new URL(`../node_modules/${name}/package.json`, import.meta.url);
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
        name?: string;
        version?: string;
        license?: string;
    };
    const identity = `${manifest.name ?? name}@${manifest.version ?? "unknown"}`;
    if (!manifest.license || !allowed.has(manifest.license)) {
        rejected.push(`${identity}: ${manifest.license ?? "missing license"}`);
    }
}

if (rejected.length > 0) {
    throw new Error(`dependency license policy rejected:\n${rejected.join("\n")}`);
}

console.log(`Dependency licenses approved (${packages.length} packages).`);
