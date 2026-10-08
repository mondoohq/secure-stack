// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0

// Builds the Slack payloads for release notifications.
//
// A release posts one message when it starts (every stage pending) and then
// updates that same message in place with the final status of each stage. The
// payload is built here rather than in workflow expressions so the status logic
// is readable and unit-tested.
//
// Usage (from release.yml):
//   node scripts/slack-release-message.mjs start > payload.json
//   node scripts/slack-release-message.mjs final > payload.json
//
// Inputs come from the environment:
//   SLACK_CHANNEL       channel ID to post to (start), or of the message (final)
//   SLACK_TS            ts of the message to update (final only)
//   SLACK_ALERT_GROUP   optional Slack user-group ID to mention when a release needs attention
//   RELEASE_VERSION     version or tag being released, e.g. v2.0.0 (the leading v is optional)
//   RESULT_RELEASE      the release job result: success | failure | cancelled | skipped
//   GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID, GITHUB_ACTOR, GITHUB_EVENT_NAME

import path from "node:path";
import { pathToFileURL } from "node:url";

// STAGES are the release jobs reported in the message, in pipeline order. The
// skills hub ships through the plugin marketplace straight from the repo, so a
// release is a single stage: the tag + GitHub Release. Add entries here if the
// release ever gains publish/verify stages.
export const STAGES = [
  { key: "release", label: "GitHub release", done: "Tagged & GitHub Release created" },
];

const ICON = {
  pending: ":hourglass_flowing_sand:",
  success: ":white_check_mark:",
  failure: ":x:",
  cancelled: ":no_entry_sign:",
  skipped: ":double_vertical_bar:",
};

// stageText renders one stage's status line.
export function stageText(stage, result) {
  switch (result) {
    case "pending":
      return `${ICON.pending} Pending`;
    case "success":
      return `${ICON.success} ${stage.done}`;
    case "failure":
      return `${ICON.failure} Failed`;
    case "cancelled":
      return `${ICON.cancelled} Cancelled`;
    case "skipped":
      return `${ICON.skipped} Not run`;
    default:
      return `${ICON.failure} Unknown (${result || "no result"})`;
  }
}

// outcome classifies the release from its stage results.
export function outcome(results) {
  if (STAGES.every((s) => results[s.key] === "success")) return "success";
  if (STAGES.some((s) => results[s.key] === "cancelled")) return "cancelled";
  return "failure";
}

function context(env) {
  const repo = env.GITHUB_REPOSITORY || "mondoohq/secure-stack";
  const server = env.GITHUB_SERVER_URL || "https://github.com";
  const version = (env.RELEASE_VERSION || "unknown").replace(/^v/, "");
  return {
    repo,
    name: repo.split("/").pop(),
    version,
    tag: `v${version}`,
    actor: env.GITHUB_ACTOR || "unknown",
    trigger: env.GITHUB_EVENT_NAME || "unknown",
    runUrl: `${server}/${repo}/actions/runs/${env.GITHUB_RUN_ID || ""}`,
    releaseUrl: `${server}/${repo}/releases/tag/v${version}`,
    channel: env.SLACK_CHANNEL || "",
    ts: env.SLACK_TS || "",
    alertGroup: env.SLACK_ALERT_GROUP || "",
  };
}

function detailFields(c) {
  return {
    type: "section",
    fields: [
      { type: "mrkdwn", text: `*Repository:*\n\`${c.repo}\`` },
      { type: "mrkdwn", text: `*Version:*\n\`${c.tag}\`` },
      { type: "mrkdwn", text: `*Triggered by:*\n${c.actor} (${c.trigger})` },
    ],
  };
}

function stageFields(results) {
  return {
    type: "section",
    fields: STAGES.map((s) => ({ type: "mrkdwn", text: `*${s.label}:*\n${stageText(s, results[s.key])}` })),
  };
}

function runLink(c) {
  return { type: "context", elements: [{ type: "mrkdwn", text: `<${c.runUrl}|Open workflow run>` }] };
}

// buildStart is the message posted when the release begins.
export function buildStart(env) {
  const c = context(env);
  const pending = Object.fromEntries(STAGES.map((s) => [s.key, "pending"]));
  return {
    channel: c.channel,
    unfurl_links: false,
    unfurl_media: false,
    text: `${c.name} ${c.tag} release started`,
    blocks: [
      { type: "header", text: { type: "plain_text", text: `${c.name} ${c.tag} release started`, emoji: true } },
      detailFields(c),
      stageFields(pending),
      runLink(c),
    ],
  };
}

// buildFinal is the update applied to the start message when the release ends.
export function buildFinal(env) {
  const c = context(env);
  const results = { release: env.RESULT_RELEASE };
  const result = outcome(results);
  const mention = result === "failure" && c.alertGroup ? `<!subteam^${c.alertGroup}> ` : "";

  let header;
  let summary;
  if (result === "success") {
    header = `${c.name} ${c.tag} release completed ✓`;
    summary = `:white_check_mark: *${c.name} ${c.version} is live.* <${c.releaseUrl}|GitHub release>`;
  } else if (result === "cancelled") {
    header = `${c.name} ${c.tag} release cancelled`;
    summary = ":no_entry_sign: *The release was cancelled before it finished.* Re-run the workflow.";
  } else {
    header = `${c.name} ${c.tag} release needs attention`;
    summary = `:rotating_light: ${mention}*The release did not complete.* Check the failed stage below.`;
  }

  return {
    channel: c.channel,
    ts: c.ts,
    text: `${mention}${header}`,
    blocks: [
      { type: "header", text: { type: "plain_text", text: header, emoji: true } },
      { type: "section", text: { type: "mrkdwn", text: summary } },
      detailFields(c),
      stageFields(results),
      runLink(c),
    ],
  };
}

// Run only when invoked directly, so tests can import the builders.
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const kind = process.argv[2];
  const build = { start: buildStart, final: buildFinal }[kind];
  if (!build) {
    process.stderr.write("usage: slack-release-message.mjs start|final\n");
    process.exit(2);
  }
  process.stdout.write(JSON.stringify(build(process.env), null, 2) + "\n");
}
