// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the Slack release message builder.
//
// Run: node --test scripts/slack-release-message.test.mjs

import assert from "node:assert/strict";
import test from "node:test";

import { STAGES, buildFinal, buildStart, outcome, stageText } from "./slack-release-message.mjs";

const base = {
  SLACK_CHANNEL: "C123",
  SLACK_TS: "1700000000.000100",
  RELEASE_VERSION: "v2.0.0",
  GITHUB_REPOSITORY: "mondoohq/secure-stack",
  GITHUB_SERVER_URL: "https://github.com",
  GITHUB_RUN_ID: "42",
  GITHUB_ACTOR: "octocat",
  GITHUB_EVENT_NAME: "push",
};

// texts flattens every mrkdwn field and text in a payload, for assertions.
function texts(payload) {
  return payload.blocks.flatMap((b) => [
    ...(b.text ? [b.text.text] : []),
    ...(b.fields || []).map((f) => f.text),
    ...(b.elements || []).map((e) => e.text),
  ]);
}

test("start message shows the stage pending and links the run", () => {
  const p = buildStart(base);
  assert.equal(p.channel, "C123");
  assert.equal(p.ts, undefined, "a new message has no ts");
  assert.equal(p.blocks[0].text.text, "secure-stack v2.0.0 release started");
  const t = texts(p).join("\n");
  assert.match(t, /GitHub release:\*\n:hourglass_flowing_sand: Pending/);
  assert.match(t, /Open workflow run/);
  assert.match(t, /`mondoohq\/secure-stack`/);
});

test("final success says live and links the GitHub release, keeping the ts", () => {
  const p = buildFinal({ ...base, RESULT_RELEASE: "success" });
  assert.equal(p.ts, "1700000000.000100", "updates the same message");
  assert.equal(p.blocks[0].text.text, "secure-stack v2.0.0 release completed ✓");
  const t = texts(p).join("\n");
  assert.match(t, /secure-stack 2\.0\.0 is live/);
  assert.match(t, /releases\/tag\/v2\.0\.0\|GitHub release/);
  assert.match(t, /GitHub release:\*\n:white_check_mark: Tagged & GitHub Release created/);
});

test("final failure needs attention and mentions the alert group", () => {
  const p = buildFinal({ ...base, RESULT_RELEASE: "failure", SLACK_ALERT_GROUP: "S999" });
  assert.equal(p.blocks[0].text.text, "secure-stack v2.0.0 release needs attention");
  const t = texts(p).join("\n");
  assert.match(t, /<!subteam\^S999>/);
  assert.match(t, /:x: Failed/);
  // the top-level text (the notification line) also carries the mention
  assert.match(p.text, /<!subteam\^S999>/);
});

test("final failure without an alert group still reports, no mention", () => {
  const p = buildFinal({ ...base, RESULT_RELEASE: "failure" });
  const t = texts(p).join("\n");
  assert.doesNotMatch(t, /subteam/);
  assert.match(t, /did not complete/);
});

test("final cancelled is distinct from failure", () => {
  const p = buildFinal({ ...base, RESULT_RELEASE: "cancelled" });
  assert.equal(p.blocks[0].text.text, "secure-stack v2.0.0 release cancelled");
  assert.match(texts(p).join("\n"), /was cancelled/);
});

test("version is normalized whether or not RELEASE_VERSION has a leading v", () => {
  const withV = buildStart({ ...base, RELEASE_VERSION: "v2.0.0" });
  const noV = buildStart({ ...base, RELEASE_VERSION: "2.0.0" });
  assert.equal(withV.blocks[0].text.text, noV.blocks[0].text.text);
  assert.match(texts(noV).join("\n"), /`v2\.0\.0`/);
});

test("outcome and stageText cover each job result", () => {
  assert.equal(outcome({ release: "success" }), "success");
  assert.equal(outcome({ release: "failure" }), "failure");
  assert.equal(outcome({ release: "cancelled" }), "cancelled");
  assert.equal(outcome({ release: "skipped" }), "failure"); // a skipped release did not ship
  const stage = STAGES[0];
  assert.match(stageText(stage, "success"), /Tagged & GitHub Release created/);
  assert.match(stageText(stage, "pending"), /Pending/);
  assert.match(stageText(stage, "failure"), /Failed/);
  assert.match(stageText(stage, "weird"), /Unknown \(weird\)/);
});
