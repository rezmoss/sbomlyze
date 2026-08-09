'use strict';

const crypto = require('node:crypto');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { installBinary } = require('./download');
const { upsertComment } = require('./github');
const { runProcess } = require('./process');

const MAX_INPUT_BYTES = 50 * 1024 * 1024;
const MAX_SUMMARY_CHARS = 900_000;
const DEFAULT_VERSION = 'v0.4.0'; // x-release-please-version
const EMPTY_CYCLONEDX = '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}\n';
const FAIL_ON_VALUES = new Set(['policy', 'integrity-drift', 'any-change', 'never']);

function workflowEscape(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function emitError(message) {
  process.stdout.write(`::error::${workflowEscape(message)}\n`);
}

function createLogger() {
  return {
    info: (message) => process.stdout.write(`${message}\n`),
    warning: (message) => process.stdout.write(`::warning::${workflowEscape(message)}\n`),
  };
}

function input(env, name, fallback = '') {
  const key = `INPUT_${name.toUpperCase()}`;
  return (env[key] ?? env[key.replace(/-/g, '_')] ?? fallback).trim();
}

function booleanInput(value, name) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function relativeRepositoryPath(value, name) {
  if (!value || value.includes('\0') || /[\r\n]/.test(value)) throw new Error(`${name} must be a non-empty repository-relative path`);
  const portable = value.replace(/\\/g, '/');
  if (path.posix.isAbsolute(portable) || path.win32.isAbsolute(value) || portable.includes(':')) {
    throw new Error(`${name} must be a repository-relative path`);
  }
  const normalized = path.posix.normalize(portable);
  if (portable.split('/').includes('..') || normalized === '..' || normalized.startsWith('../') || normalized === '.') {
    throw new Error(`${name} contains path traversal`);
  }
  return normalized;
}

async function workspaceFile(workspace, value, name, maxBytes = MAX_INPUT_BYTES) {
  const relative = relativeRepositoryPath(value, name);
  const root = await fsp.realpath(workspace);
  const candidate = path.resolve(root, ...relative.split('/'));
  const real = await fsp.realpath(candidate).catch(() => null);
  if (!real) throw new Error(`${name} does not exist: ${relative}`);
  const fromRoot = path.relative(root, real);
  if (fromRoot.startsWith('..') || path.isAbsolute(fromRoot)) throw new Error(`${name} resolves outside GITHUB_WORKSPACE`);
  const stat = await fsp.stat(real);
  if (!stat.isFile()) throw new Error(`${name} is not a regular file`);
  if (stat.size > maxBytes) throw new Error(`${name} exceeds the ${maxBytes}-byte limit`);
  return { absolute: real, relative };
}

async function readEvent(env) {
  if (!env.GITHUB_EVENT_PATH) return {};
  const stat = await fsp.stat(env.GITHUB_EVENT_PATH);
  if (stat.size > 2 * 1024 * 1024) throw new Error('GitHub event payload is unexpectedly large');
  return JSON.parse(await fsp.readFile(env.GITHUB_EVENT_PATH, 'utf8'));
}

function baselineRevision(env, event) {
  const baseSHA = event.pull_request?.base?.sha;
  if (baseSHA) {
    if (!/^[0-9a-f]{40,64}$/i.test(baseSHA)) throw new Error('pull request base SHA is invalid');
    return baseSHA;
  }
  const before = event.before;
  if (before && !/^0+$/.test(before)) {
    if (!/^[0-9a-f]{40,64}$/i.test(before)) throw new Error('push baseline SHA is invalid');
    return before;
  }
  if (env.GITHUB_EVENT_NAME === 'push' && before && /^0+$/.test(before)) return null;
  return 'HEAD^';
}

async function resolveGitBaseline({ workspace, basePath, outputPath, env, event, run = runProcess }) {
  const revision = baselineRevision(env, event);
  if (revision === null) {
    await fsp.writeFile(outputPath, EMPTY_CYCLONEDX, { mode: 0o600 });
    return { firstRun: true, revision: null };
  }
  const commit = await run('git', ['cat-file', '-e', `${revision}^{commit}`], { cwd: workspace, env, maxOutput: 1024 * 1024 });
  if (commit.code !== 0) {
    throw new Error(`git baseline ${revision} is unavailable; use actions/checkout with enough history to include the base commit`);
  }
  const object = await run('git', ['cat-file', '-e', `${revision}:${basePath}`], { cwd: workspace, env, maxOutput: 1024 * 1024 });
  if (object.code !== 0) {
    await fsp.writeFile(outputPath, EMPTY_CYCLONEDX, { mode: 0o600 });
    return { firstRun: true, revision };
  }
  const shown = await run('git', ['show', `${revision}:${basePath}`], { cwd: workspace, env, maxOutput: MAX_INPUT_BYTES + 1 });
  if (shown.code !== 0) throw new Error(`could not read ${basePath} from git baseline ${revision}: ${shown.stderr.trim()}`);
  const bytes = Buffer.byteLength(shown.stdout);
  if (bytes > MAX_INPUT_BYTES) throw new Error(`baseline SBOM exceeds the ${MAX_INPUT_BYTES}-byte limit`);
  await fsp.writeFile(outputPath, shown.stdout, { mode: 0o600 });
  return { firstRun: false, revision };
}

async function runSBOMlyze(binary, baseline, head, policy, format, env) {
  const args = [baseline, head, '--strict', '--no-pager', '--format', format];
  if (policy) args.push('--policy', policy);
  const result = await runProcess(binary, args, { env: { ...env, TERM: 'dumb' } });
  if (result.code !== 0 && result.code !== 1) {
    throw new Error(`sbomlyze ${format} failed: ${result.stderr.trim() || `exit code ${result.code}`}`);
  }
  if (!result.stdout.trim()) {
    throw new Error(`sbomlyze rejected an input: ${result.stderr.trim() || 'no report produced'}`);
  }
  return result.stdout;
}

function countsFromReport(report) {
  const diff = report && report.diff;
  if (!diff || typeof diff !== 'object') throw new Error('SBOMlyze JSON report has no diff object');
  const count = (value) => Array.isArray(value) ? value.length : 0;
  const integrity = diff.drift_summary?.integrity_drift ?? 0;
  if (!Number.isSafeInteger(integrity) || integrity < 0) throw new Error('invalid integrity drift count in report');
  return { added: count(diff.added), removed: count(diff.removed), changed: count(diff.changed), integrity };
}

function policyFailed(report) {
  return Array.isArray(report.violations) && report.violations.some((violation) => violation && violation.severity === 'error');
}

function verdictFor(failOn, report, counts) {
  switch (failOn) {
    case 'policy': return policyFailed(report) ? 'fail' : 'pass';
    case 'integrity-drift': return counts.integrity > 0 ? 'fail' : 'pass';
    case 'any-change': return counts.added + counts.removed + counts.changed > 0 ? 'fail' : 'pass';
    case 'never': return 'pass';
    default: throw new Error(`unsupported fail-on value: ${failOn}`);
  }
}

async function appendFileCommand(filename, name, value) {
  if (!filename) return;
  const delimiter = `sbomlyze_${crypto.randomUUID()}`;
  await fsp.appendFile(filename, `${name}<<${delimiter}\n${value}\n${delimiter}\n`, 'utf8');
}

async function setOutputs(env, values) {
  for (const [name, value] of Object.entries(values)) {
    await appendFileCommand(env.GITHUB_OUTPUT, name, String(value));
  }
}

function summaryPreamble(verdict, counts, baseline) {
  const icon = verdict === 'pass' ? '✅' : '❌';
  return `# ${icon} SBOMlyze: ${verdict.toUpperCase()}\n\n` +
    `| Added | Removed | Changed | Integrity drift |\n|---:|---:|---:|---:|\n` +
    `| ${counts.added} | ${counts.removed} | ${counts.changed} | ${counts.integrity} |\n\n` +
    (baseline.firstRun ? '> No baseline SBOM existed at the selected git revision; this run used an empty baseline.\n\n' : '');
}

async function writeSummary(env, text, log) {
  if (!env.GITHUB_STEP_SUMMARY) {
    log.info(text);
    return;
  }
  const summary = text.length > MAX_SUMMARY_CHARS
    ? `${text.slice(0, MAX_SUMMARY_CHARS)}\n\n_Report truncated; use the report-markdown output for the complete report._\n`
    : text;
  await fsp.appendFile(env.GITHUB_STEP_SUMMARY, summary, 'utf8');
}

function pullRequestNumber(event) {
  const value = event.pull_request?.number ?? event.number;
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

async function runAction(env, dependencies = {}) {
  const log = dependencies.log || createLogger();
  const workspace = env.GITHUB_WORKSPACE || process.cwd();
  const sbomValue = input(env, 'sbom-path');
  const baseValue = input(env, 'base-sbom-path') || sbomValue;
  const baselineType = input(env, 'baseline', 'git');
  const policyValue = input(env, 'policy');
  const comment = booleanInput(input(env, 'comment', 'false'), 'comment');
  const githubToken = input(env, 'github-token') || env.GITHUB_TOKEN || '';
  const sarif = booleanInput(input(env, 'sarif', 'false'), 'sarif');
  const failOn = input(env, 'fail-on', 'policy');
  const version = input(env, 'version', DEFAULT_VERSION);
  if (baselineType !== 'git') throw new Error(`baseline ${JSON.stringify(baselineType)} is not supported yet; this MVP supports git`);
  if (!FAIL_ON_VALUES.has(failOn)) throw new Error('fail-on must be policy, integrity-drift, any-change, or never');

  const head = await workspaceFile(workspace, sbomValue, 'sbom-path');
  const basePath = relativeRepositoryPath(baseValue, 'base-sbom-path');
  const policy = policyValue ? await workspaceFile(workspace, policyValue, 'policy') : null;
  const event = dependencies.event || await readEvent(env);
  const tempRoot = env.RUNNER_TEMP || os.tmpdir();
  const runDirectory = await fsp.mkdtemp(path.join(tempRoot, 'sbomlyze-action-'));
  const baselinePath = path.join(runDirectory, 'baseline.json');
  const baseline = await (dependencies.resolveBaseline || resolveGitBaseline)({
    workspace, basePath, outputPath: baselinePath, env, event,
  });

  const commandEnv = githubToken && !env.GH_TOKEN ? { ...env, GH_TOKEN: githubToken } : env;
  const binary = dependencies.binaryPath || await (dependencies.installBinary || installBinary)(version, runDirectory, commandEnv, log);
  const jsonPath = path.join(runDirectory, 'report.json');
  const markdownPath = path.join(runDirectory, 'report.md');
  const sarifPath = sarif ? path.join(runDirectory, 'report.sarif') : '';
  const render = dependencies.runSBOMlyze || runSBOMlyze;
  const jsonText = await render(binary, baselinePath, head.absolute, policy?.absolute, 'json', env);
  let report;
  try { report = JSON.parse(jsonText); } catch (error) { throw new Error(`could not parse SBOMlyze JSON report: ${error.message}`); }
  const markdown = await render(binary, baselinePath, head.absolute, policy?.absolute, 'markdown', env);
  await fsp.writeFile(jsonPath, jsonText, { mode: 0o600 });
  await fsp.writeFile(markdownPath, markdown, { mode: 0o600 });
  if (sarif) {
    const sarifText = await render(binary, baselinePath, head.absolute, policy?.absolute, 'sarif', env);
    JSON.parse(sarifText);
    await fsp.writeFile(sarifPath, sarifText, { mode: 0o600 });
  }

  const counts = countsFromReport(report);
  const verdict = verdictFor(failOn, report, counts);
  await setOutputs(env, {
    verdict,
    'added-count': counts.added,
    'removed-count': counts.removed,
    'changed-count': counts.changed,
    'integrity-drift-count': counts.integrity,
    'report-json': jsonPath,
    'report-markdown': markdownPath,
    'report-sarif': sarifPath,
  });
  const fullSummary = summaryPreamble(verdict, counts, baseline) + markdown;
  await writeSummary(env, fullSummary, log);

  if (comment) {
    const issueNumber = pullRequestNumber(event);
    const token = githubToken;
    if (!issueNumber) log.warning('comment=true, but this event is not a pull request; Job Summary is still available.');
    else if (!token) log.warning('comment=true, but GITHUB_TOKEN was not provided; Job Summary is still available.');
    else {
      try {
        const operation = await (dependencies.upsertComment || upsertComment)({
          repository: env.GITHUB_REPOSITORY,
          issueNumber,
          token,
          markdown: fullSummary,
        });
        log.info(`Pull request comment ${operation}.`);
      } catch (error) {
        if (error.status === 403 || error.status === 404) {
          log.warning('Pull request comment permission is unavailable; Job Summary contains the complete result.');
        } else throw error;
      }
    }
  }

  return {
    failed: verdict === 'fail',
    message: verdict === 'fail' ? `SBOMlyze failed the ${failOn} gate` : '',
    verdict, counts, report, paths: { json: jsonPath, markdown: markdownPath, sarif: sarifPath }, baseline,
  };
}

module.exports = {
  EMPTY_CYCLONEDX,
  MAX_INPUT_BYTES,
  baselineRevision,
  countsFromReport,
  emitError,
  input,
  relativeRepositoryPath,
  resolveGitBaseline,
  runAction,
  runSBOMlyze,
  verdictFor,
  workspaceFile,
};
