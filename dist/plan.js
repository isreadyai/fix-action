#!/usr/bin/env node
// @bun

// fix-action/plan.ts
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
function env(name) {
  const value = process.env[name];
  return value !== undefined && value.length > 0 ? value : undefined;
}
async function main() {
  const apiKey = env("ISREADYAI_API_KEY");
  const apiUrl = env("ISREADYAI_API_URL") ?? "https://isready.ai";
  const reportPath = env("REPORT_PATH");
  const fixDir = env("FIX_DIR");
  if (apiKey === undefined || reportPath === undefined || fixDir === undefined) {
    return;
  }
  let report;
  try {
    report = JSON.parse(readFileSync(reportPath, "utf8"));
  } catch {
    return;
  }
  const response = await fetch(`${apiUrl}/api/fix-plan`, {
    method: "POST",
    headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
    body: JSON.stringify({ repo: process.env.GITHUB_REPOSITORY ?? "unknown", report })
  }).catch(() => null);
  if (response === null || !response.ok) {
    return;
  }
  const data = await response.json().catch(() => null);
  const plan = typeof data?.plan === "string" ? data.plan.trim() : "";
  if (plan.length === 0) {
    return;
  }
  const prBody = join(fixDir, "pr-body.md");
  const section = `
## AI fix plan

${plan}
`;
  if (existsSync(prBody)) {
    appendFileSync(prBody, section);
  } else {
    writeFileSync(prBody, section.trimStart());
  }
  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary !== undefined) {
    appendFileSync(summary, `# isready.ai \u2014 AI fix plan

${plan}
`);
  }
}
if (true) {
  await main();
}
