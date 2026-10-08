#!/usr/bin/env npx tsx
/**
 * Generate agents/SKILLS.md from SKILLS_TEMPLATE.md and SKILL.md frontmatter.
 *
 * Also validates that marketplace.json is in sync with discovered skills,
 * that every skill's plugin.json carries the repo-wide release version,
 * and updates the skills table in README.md.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { join, dirname, relative } from "path";

const ROOT = join(dirname(new URL(import.meta.url).pathname), "..");
const TEMPLATE_PATH = join(ROOT, "scripts", "SKILLS_TEMPLATE.md");
const OUTPUT_PATH = join(ROOT, "agents", "SKILLS.md");
const MARKETPLACE_PATH = join(ROOT, ".claude-plugin", "marketplace.json");
const PLUGIN_PATH = join(ROOT, ".claude-plugin", "plugin.json");
const README_PATH = join(ROOT, "README.md");

const README_TABLE_START = "<!-- BEGIN_SKILLS_TABLE -->";
const README_TABLE_END = "<!-- END_SKILLS_TABLE -->";
const README_INTEGRATIONS_START = "<!-- BEGIN_INTEGRATIONS_TABLE -->";
const README_INTEGRATIONS_END = "<!-- END_INTEGRATIONS_TABLE -->";

interface Skill {
  name: string;
  description: string;
  path: string;
}

/**
 * The secure-guard adapters, one per coding agent. All run the same two
 * engines (xgrep + cnspec) through the shared core/engine; only the agent's I/O
 * differs. This list is the source of truth for the README integrations table
 * and is validated against disk (each `entry` and a README must exist) so an
 * adapter can't be listed but missing, or shipped but undocumented.
 */
interface Integration {
  agent: string;
  shape: string;
  dir: string;
  entry: string;
  install: string;
  posture: string;
}

const INTEGRATIONS: Integration[] = [
  {
    agent: "Claude Code",
    shape: "in-process mod",
    dir: "mods/secure-guard",
    entry: "hooks/secure-guard.mjs",
    install: "`/plugin install secure-guard@secure-stack`",
    posture: "shell blocks; code/IaC advisory (post-write)",
  },
  {
    agent: "OpenAI Codex",
    shape: "external pre-tool hook",
    dir: "integrations/codex",
    entry: "install.mjs",
    install: "`node integrations/codex/install.mjs`",
    posture: "shell + code + IaC block (pre-write)",
  },
  {
    agent: "Mistral Vibe",
    shape: "external pre-tool hook",
    dir: "integrations/vibe",
    entry: "install.mjs",
    install: "`node integrations/vibe/install.mjs`",
    posture: "shell + code + IaC deny (pre-write)",
  },
  {
    agent: "Pi",
    shape: "in-process TS extension",
    dir: "integrations/pi",
    entry: "index.ts",
    install: "load `integrations/pi` as a Pi extension",
    posture: "block (pre-write); `ask` via `ctx.ui.confirm`",
  },
  {
    agent: "opencode",
    shape: "in-process TS plugin",
    dir: "integrations/opencode",
    entry: "plugin.ts",
    install: "copy `plugin.ts` into `.opencode/plugins/`",
    posture: "deny via throw (pre-write); no native `ask`",
  },
];

interface MarketplacePlugin {
  name: string;
  source: string;
  description?: string;
}

function parseFrontmatter(text: string): Record<string, string> {
  const match = text.match(/^---\s*\n(.*?)\n---\s*/s);
  if (!match) return {};
  const data: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    data[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return data;
}

function collectSkills(): Skill[] {
  const skillsDir = join(ROOT, "skills");
  if (!existsSync(skillsDir)) return [];

  const skills: Skill[] = [];
  for (const entry of readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const skillMd = join(skillsDir, entry.name, "SKILL.md");
    if (!existsSync(skillMd)) continue;

    const meta = parseFrontmatter(readFileSync(skillMd, "utf-8"));
    if (!meta.name || !meta.description) continue;

    skills.push({
      name: meta.name,
      description: meta.description,
      path: relative(ROOT, join(skillsDir, entry.name)),
    });
  }

  return skills.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
}

/**
 * Semver X.Y.Z with an optional prerelease suffix (2.0.0-rc.1). Build metadata
 * (+…) is deliberately excluded: it would end up in a git tag and a GitHub
 * Release title, and it never affects precedence.
 *
 * Keep this in sync with the `version` input regex in
 * .github/workflows/prepare-release.yml. If the workflow accepts a shape this
 * rejects, the release run dies inside publish.sh and no PR is ever opened.
 */
const VERSION_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

interface VersionedManifest {
  version?: string;
  metadata?: { version?: string };
}

/** Assert one manifest carries `expected`, reading the version via `pick`. */
function checkManifestVersion(
  rel: string,
  expected: string,
  pick: (m: VersionedManifest) => string | undefined
): string[] {
  const path = join(ROOT, rel);
  if (!existsSync(path)) {
    return [`${rel} is missing — the release stamping step expects it to exist`];
  }
  let manifest: VersionedManifest;
  try {
    manifest = JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    return [`${rel} is not valid JSON`];
  }
  const found = pick(manifest);
  if (found !== expected) {
    return [
      `Version drift in ${rel}: '${found}' != root '${expected}'. ` +
        `Versions are stamped by the release workflow; do not edit them by hand.`,
    ];
  }
  return [];
}

/**
 * Manifests outside skills/ that must all carry the repo-wide version.
 * `top` files hold `.version`; `metadata` files hold `.metadata.version`
 * (writing the wrong one adds an off-schema key and leaves the real version
 * stale, so the distinction matters).
 */
const SIBLING_TOP_MANIFESTS = [".cursor-plugin/plugin.json", "gemini-extension.json"];
const SIBLING_METADATA_MANIFESTS = [
  ".claude-plugin/marketplace.json",
  ".cursor-plugin/marketplace.json",
];

/**
 * Every skill ships one repo-wide version, stamped by the Prepare Release
 * workflow (.github/workflows/prepare-release.yml) — never edited by hand.
 *
 * This check exists because a stale version is silent and expensive: Claude
 * Code's `plugin update` compares the version in a skill's plugin.json and
 * skips the copy when it hasn't moved, so installed users keep the old content
 * indefinitely. cnspec shipped four months of skill fixes nobody received that
 * way (mondoohq/cnspec#3613). Failing the build is how that stays impossible
 * here.
 */
function validateVersions(skills: Skill[]): string[] {
  const errors: string[] = [];
  const rootVersion = loadRootVersion();

  if (!VERSION_RE.test(rootVersion)) {
    errors.push(
      `Root .claude-plugin/plugin.json version '${rootVersion}' is not semver (X.Y.Z or X.Y.Z-pre)`
    );
  }

  // The stamping step writes these too, so check them here — otherwise a
  // renamed or removed manifest silently ships unstamped and, say, Gemini users
  // never see an update.
  for (const rel of SIBLING_TOP_MANIFESTS) {
    errors.push(...checkManifestVersion(rel, rootVersion, (m) => m.version));
  }
  for (const rel of SIBLING_METADATA_MANIFESTS) {
    errors.push(...checkManifestVersion(rel, rootVersion, (m) => m.metadata?.version));
  }

  for (const skill of skills) {
    const manifestPath = join(ROOT, skill.path, ".claude-plugin", "plugin.json");
    if (!existsSync(manifestPath)) {
      errors.push(
        `Skill '${skill.name}' is missing ${relative(ROOT, manifestPath)} — ` +
          `without it the plugin has no version and cannot be updated in place`
      );
      continue;
    }

    let manifest: { name?: string; version?: string };
    try {
      manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
    } catch {
      errors.push(`Skill '${skill.name}': ${relative(ROOT, manifestPath)} is not valid JSON`);
      continue;
    }

    if (manifest.name !== skill.name) {
      errors.push(
        `Name mismatch in ${relative(ROOT, manifestPath)}: ` +
          `SKILL.md='${skill.name}', plugin.json='${manifest.name}'`
      );
    }
    if (manifest.version !== rootVersion) {
      errors.push(
        `Version drift in ${relative(ROOT, manifestPath)}: ` +
          `'${manifest.version}' != root '${rootVersion}'. ` +
          `Versions are stamped by the release workflow; do not edit them by hand.`
      );
    }
  }

  return errors;
}

function render(template: string, skills: Skill[]): string {
  return template.replace(/\{\{#skills\}\}(.*?)\{\{\/skills\}\}/gs, (_, block: string) => {
    const trimmed = block.replace(/^\n/, "").replace(/\n$/, "");
    return skills
      .map((s) =>
        trimmed
          .replace(/\{\{name\}\}/g, s.name)
          .replace(/\{\{description\}\}/g, s.description)
          .replace(/\{\{path\}\}/g, s.path)
      )
      .join("\n");
  });
}

function loadMarketplace(): { plugins: MarketplacePlugin[] } {
  if (!existsSync(MARKETPLACE_PATH)) {
    throw new Error(`marketplace.json not found at ${MARKETPLACE_PATH}`);
  }
  return JSON.parse(readFileSync(MARKETPLACE_PATH, "utf-8"));
}

/** The single release version every skill inherits. */
function loadRootVersion(): string {
  if (!existsSync(PLUGIN_PATH)) {
    throw new Error(`plugin.json not found at ${PLUGIN_PATH}`);
  }
  const plugin = JSON.parse(readFileSync(PLUGIN_PATH, "utf-8"));
  if (!plugin.version) {
    throw new Error(`No version in ${PLUGIN_PATH}`);
  }
  return plugin.version;
}

function generateReadmeTable(skills: Skill[]): string {
  const marketplace = loadMarketplace();
  const plugins = new Map(marketplace.plugins.map((p) => [p.source, p]));

  const lines = [
    "| Name | Description | Documentation |",
    "|------|-------------|---------------|",
  ];

  for (const skill of skills) {
    const source = `./${skill.path}`;
    const plugin = plugins.get(source);
    const name = plugin?.name ?? skill.name;
    const description = plugin?.description ?? skill.description;
    const docLink = `[SKILL.md](${skill.path}/SKILL.md)`;
    lines.push(`| \`${name}\` | ${description} | ${docLink} |`);
  }

  return lines.join("\n");
}

/** Replace the text between a start/end marker in `content`, keeping the markers. */
function replaceMarked(content: string, start: string, end: string, body: string): string | null {
  const startIdx = content.indexOf(start);
  const endIdx = content.indexOf(end);
  if (startIdx === -1 || endIdx === -1) {
    console.error(`Warning: README.md markers not found (${start} / ${end}).`);
    return null;
  }
  if (endIdx < startIdx) {
    console.error(`Warning: README.md markers are in wrong order (${start} / ${end}).`);
    return null;
  }
  return content.slice(0, startIdx + start.length) + "\n" + body + "\n" + content.slice(endIdx);
}

function generateIntegrationsTable(): string {
  const lines = [
    "| Agent | Shape | Install | Posture |",
    "|-------|-------|---------|---------|",
  ];
  for (const i of INTEGRATIONS) {
    lines.push(`| **${i.agent}** | ${i.shape} | ${i.install} | ${i.posture} |`);
  }
  return lines.join("\n");
}

function updateReadme(skills: Skill[]): boolean {
  if (!existsSync(README_PATH)) {
    console.error(`Warning: README.md not found at ${README_PATH}`);
    return false;
  }

  let content = readFileSync(README_PATH, "utf-8");
  const withSkills = replaceMarked(content, README_TABLE_START, README_TABLE_END, generateReadmeTable(skills));
  if (withSkills === null) return false;
  content = withSkills;

  // The integrations table is optional: regenerate it only if the markers exist.
  if (content.includes(README_INTEGRATIONS_START)) {
    const withIntegrations = replaceMarked(
      content, README_INTEGRATIONS_START, README_INTEGRATIONS_END, generateIntegrationsTable()
    );
    if (withIntegrations === null) return false;
    content = withIntegrations;
  }

  writeFileSync(README_PATH, content, "utf-8");
  return true;
}

/**
 * A valid Agent Skills `name`: 1-64 lowercase alphanumerics in single-hyphen
 * segments — no leading/trailing hyphen, no consecutive hyphens, no uppercase.
 * https://agentskills.io/specification
 */
const SKILL_NAME_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;

/**
 * Enforce the Agent Skills spec on every skill so "we follow the spec" is a
 * check, not a claim: the `name` must be a valid slug that equals its directory,
 * and `description` must be 1-1024 chars. Also catch a skills/<dir>/SKILL.md that
 * failed to parse into a usable skill — collectSkills() silently skips those, so
 * without this they vanish from the bundle with no error.
 */
function validateSkillSpec(skills: Skill[]): string[] {
  const errors: string[] = [];
  const collectedDirs = new Set<string>();

  for (const s of skills) {
    const dir = s.path.split("/").pop() ?? s.path;
    collectedDirs.add(dir);
    if (s.name !== dir) {
      errors.push(
        `Skill '${s.name}': frontmatter name must equal its directory ('${dir}') per the Agent Skills spec`
      );
    }
    if (s.name.length > 64 || !SKILL_NAME_RE.test(s.name)) {
      errors.push(
        `Skill '${s.name}': name must be 1-64 chars, lowercase a-z/0-9 in single-hyphen segments ` +
          `(no leading/trailing hyphen, no '--')`
      );
    }
    const desc = s.description ?? "";
    if (desc.trim().length < 1 || desc.length > 1024) {
      errors.push(
        `Skill '${s.name}': description must be 1-1024 characters (found ${desc.length})`
      );
    }
  }

  const skillsDir = join(ROOT, "skills");
  if (existsSync(skillsDir)) {
    for (const entry of readdirSync(skillsDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      if (!existsSync(join(skillsDir, entry.name, "SKILL.md"))) continue;
      if (!collectedDirs.has(entry.name)) {
        errors.push(
          `skills/${entry.name}/SKILL.md has no valid 'name'+'description' frontmatter — ` +
            `it would be silently dropped from the bundle`
        );
      }
    }
  }

  return errors;
}

/**
 * Every listed secure-guard adapter must exist on disk with its entry file
 * and a README — a listed-but-missing adapter would ship a broken install link,
 * and a shipped-but-undocumented one would be undiscoverable.
 */
function validateIntegrations(): string[] {
  const errors: string[] = [];
  for (const i of INTEGRATIONS) {
    const entry = join(ROOT, i.dir, i.entry);
    if (!existsSync(entry)) {
      errors.push(`Integration '${i.agent}': entry ${i.dir}/${i.entry} is missing`);
    }
    const readme = join(ROOT, i.dir, "README.md");
    if (!existsSync(readme)) {
      errors.push(`Integration '${i.agent}': ${i.dir}/README.md is missing`);
    }
  }
  return errors;
}

function validateMarketplace(skills: Skill[]): string[] {
  const errors: string[] = [];
  const marketplace = loadMarketplace();
  const plugins = marketplace.plugins;

  const skillBySource = new Map(skills.map((s) => [`./${s.path}`, s]));
  const pluginBySource = new Map(plugins.map((p) => [p.source, p]));

  for (const skill of skills) {
    const expectedSource = `./${skill.path}`;
    const plugin = pluginBySource.get(expectedSource);
    if (!plugin) {
      errors.push(`Skill '${skill.name}' at '${skill.path}' is missing from marketplace.json`);
    } else if (plugin.name !== skill.name) {
      errors.push(
        `Name mismatch at '${expectedSource}': SKILL.md='${skill.name}', marketplace.json='${plugin.name}'`
      );
    }
  }

  for (const plugin of plugins) {
    if (!skillBySource.has(plugin.source)) {
      errors.push(
        `Marketplace plugin '${plugin.name}' at '${plugin.source}' has no SKILL.md`
      );
    }
  }

  return errors;
}

function main(): void {
  const template = readFileSync(TEMPLATE_PATH, "utf-8");
  const skills = collectSkills();
  const output = render(template, skills);

  mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
  writeFileSync(OUTPUT_PATH, output, "utf-8");
  console.log(`Wrote ${OUTPUT_PATH} with ${skills.length} skills.`);

  const errors = validateMarketplace(skills);
  if (errors.length > 0) {
    console.error("\nMarketplace.json validation errors:");
    for (const error of errors) {
      console.error(`  - ${error}`);
    }
    process.exit(1);
  }
  console.log("Marketplace.json validation passed.");

  const specErrors = validateSkillSpec(skills);
  if (specErrors.length > 0) {
    console.error("\nAgent Skills spec validation errors:");
    for (const error of specErrors) {
      console.error(`  - ${error}`);
    }
    process.exit(1);
  }
  console.log(`Agent Skills spec OK (${skills.length} skills).`);

  const versionErrors = validateVersions(skills);
  if (versionErrors.length > 0) {
    console.error("\nPlugin version validation errors:");
    for (const error of versionErrors) {
      console.error(`  - ${error}`);
    }
    process.exit(1);
  }
  console.log(`Plugin versions consistent at ${loadRootVersion()}.`);

  const integrationErrors = validateIntegrations();
  if (integrationErrors.length > 0) {
    console.error("\nIntegration validation errors:");
    for (const error of integrationErrors) {
      console.error(`  - ${error}`);
    }
    process.exit(1);
  }
  console.log(`Integrations consistent (${INTEGRATIONS.length} agents).`);

  if (updateReadme(skills)) {
    console.log(`Updated ${README_PATH} skills table.`);
  }
}

main();
