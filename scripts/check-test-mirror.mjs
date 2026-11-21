import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);

// Client source is the @linkfuture/license-client package, not a top-level client/ folder.
const PAIRS = [
  ["server/src", "server/test"],
  ["packages/license-client/src", "packages/license-client/test"],
];

function posix(path) {
  return path.split("\\").join("/");
}

function walk(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

function isTypeOnly(srcRoot, rel) {
  const norm = posix(rel);
  if (norm.endsWith(".d.ts")) return true;
  return norm === "lib/types.ts" && posix(srcRoot).endsWith("server/src");
}

function underHelpers(rel) {
  const norm = posix(rel);
  return norm === "helpers" || norm.startsWith("helpers/");
}

export function checkTree(root, pairs = PAIRS) {
  const missing = [];
  const extra = [];
  for (const [srcRel, testRel] of pairs) {
    const srcDir = join(root, srcRel);
    const testDir = join(root, testRel);
    if (!existsSync(srcDir)) {
      missing.push(`missing source root ${posix(srcRel)}`);
      continue;
    }
    for (const file of walk(srcDir)) {
      if (!file.endsWith(".ts")) continue;
      const rel = relative(srcDir, file);
      if (isTypeOnly(srcRel, rel)) continue;
      const testFileRel = rel.replace(/\.ts$/, ".test.ts");
      if (!existsSync(join(testDir, testFileRel))) {
        missing.push(`${posix(join(srcRel, rel))} -> ${posix(join(testRel, testFileRel))}`);
      }
    }
    for (const file of walk(testDir)) {
      if (!file.endsWith(".test.ts")) continue;
      const rel = relative(testDir, file);
      if (underHelpers(rel)) continue;
      const srcFileRel = rel.replace(/\.test\.ts$/, ".ts");
      if (!existsSync(join(srcDir, srcFileRel))) {
        extra.push(`${posix(join(testRel, rel))} (no ${posix(join(srcRel, srcFileRel))})`);
      }
    }
  }
  return { missing, extra };
}

function printReport(result) {
  if (result.missing.length === 0 && result.extra.length === 0) {
    console.log("test mirror ok");
    return 0;
  }
  if (result.missing.length > 0) {
    console.error("missing:");
    for (const line of result.missing) console.error(`  ${line}`);
  }
  if (result.extra.length > 0) {
    console.error("extra:");
    for (const line of result.extra) console.error(`  ${line}`);
  }
  return 1;
}

function argValue(flag) {
  const index = process.argv.indexOf(flag);
  return index === -1 ? undefined : process.argv[index + 1];
}

function runCli(root) {
  return spawnSync(process.execPath, [scriptPath, "--root", root], { encoding: "utf8" });
}

function writeTree(root, files) {
  for (const [rel, contents] of Object.entries(files)) {
    const full = join(root, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, contents);
  }
}

function assertIncludes(text, needle, label) {
  if (!text.includes(needle)) {
    throw new Error(`${label}: expected output to include ${needle}\n${text}`);
  }
}

function assertExcludes(text, needle, label) {
  if (text.includes(needle)) {
    throw new Error(`${label}: expected output to omit ${needle}\n${text}`);
  }
}

function selfTest() {
  const bad = mkdtempSync(join(tmpdir(), "mirror-bad-"));
  const good = mkdtempSync(join(tmpdir(), "mirror-good-"));
  try {
    writeTree(bad, {
      "server/src/index.ts": "export {}\n",
      "server/test/index.test.ts": "export {}\n",
      "server/src/lib/types.ts": "export {}\n",
      "server/src/extra.d.ts": "export {}\n",
      "server/src/lib/missing.ts": "export {}\n",
      "server/test/lib/orphan.test.ts": "export {}\n",
      "server/test/helpers/sneaky.test.ts": "export {}\n",
      "packages/license-client/src/index.ts": "export {}\n",
      "packages/license-client/test/index.test.ts": "export {}\n",
    });
    const failed = runCli(bad);
    if (failed.status === 0) throw new Error("self-test: broken tree was accepted");
    const failedOut = `${failed.stdout}${failed.stderr}`;
    assertIncludes(failedOut, "server/src/lib/missing.ts -> server/test/lib/missing.test.ts", "missing");
    assertIncludes(failedOut, "server/test/lib/orphan.test.ts (no server/src/lib/orphan.ts)", "extra");
    assertExcludes(failedOut, "types.ts", "allowlist types");
    assertExcludes(failedOut, "extra.d.ts", "allowlist d.ts");
    assertExcludes(failedOut, "sneaky.test.ts", "allowlist helpers");
    assertExcludes(failedOut, "packages/license-client/src/index.ts ->", "present client test");

    writeTree(good, {
      "server/src/index.ts": "export {}\n",
      "server/test/index.test.ts": "export {}\n",
      "server/src/lib/types.ts": "export {}\n",
      "server/src/extra.d.ts": "export {}\n",
      "server/src/lib/kept.ts": "export {}\n",
      "server/test/lib/kept.test.ts": "export {}\n",
      "server/test/helpers/fixtures.ts": "export {}\n",
      "packages/license-client/src/index.ts": "export {}\n",
      "packages/license-client/test/index.test.ts": "export {}\n",
    });
    const passed = runCli(good);
    if (passed.status !== 0) {
      throw new Error(`self-test: valid tree failed\n${passed.stdout}${passed.stderr}`);
    }
    if (!passed.stdout.includes("test mirror ok")) {
      throw new Error(`self-test: valid tree did not print ok\n${passed.stdout}`);
    }
    console.log("self-test ok");
  } finally {
    rmSync(bad, { recursive: true, force: true });
    rmSync(good, { recursive: true, force: true });
  }
}

const root = argValue("--root") ?? process.cwd();
if (process.argv.includes("--self-test")) selfTest();
process.exit(printReport(checkTree(root)));
