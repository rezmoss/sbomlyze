'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  EMPTY_CYCLONEDX,
  relativeRepositoryPath,
  resolveGitBaseline,
  runAction,
  verdictFor,
  workspaceFile,
} = require('../lib/action');
const { COMMENT_MARKER, upsertComment } = require('../lib/github');
const { exactVersion, expectedChecksum, releaseAsset, validateArchiveListing } = require('../lib/download');

const repository = path.resolve(__dirname, '..', '..');
const fixtures = path.join(repository, 'testdata');
const suiteRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sbomlyze-action-tests-'));
const binary = path.join(suiteRoot, process.platform === 'win32' ? 'sbomlyze.exe' : 'sbomlyze');
execFileSync('go', ['build', '-o', binary, './cmd/sbomlyze'], {
  cwd: repository,
  env: { ...process.env, GOCACHE: path.join(suiteRoot, 'go-cache'), GOFLAGS: '-mod=mod' },
  stdio: 'inherit',
});

async function actionWorkspace() {
  const root = await fsp.mkdtemp(path.join(suiteRoot, 'workspace-'));
  await fsp.mkdir(path.join(root, 'runner-temp'));
  await fsp.writeFile(path.join(root, 'output.txt'), '');
  await fsp.writeFile(path.join(root, 'summary.md'), '');
  return root;
}

function environment(root, values = {}) {
  return {
    ...process.env,
    GITHUB_WORKSPACE: root,
    RUNNER_TEMP: path.join(root, 'runner-temp'),
    GITHUB_OUTPUT: path.join(root, 'output.txt'),
    GITHUB_STEP_SUMMARY: path.join(root, 'summary.md'),
    GITHUB_REPOSITORY: 'example/project',
    'INPUT_SBOM-PATH': 'head.json',
    'INPUT_BASELINE': 'git',
    'INPUT_COMMENT': 'false',
    'INPUT_SARIF': 'false',
    'INPUT_FAIL-ON': 'never',
    'INPUT_VERSION': 'v0.3.7',
    ...values,
  };
}

function baselineFrom(source) {
  return async ({ outputPath }) => {
    await fsp.copyFile(source, outputPath);
    return { firstRun: false, revision: 'test-base' };
  };
}

async function copy(root, source, destination = 'head.json') {
  const target = path.join(root, destination);
  await fsp.mkdir(path.dirname(target), { recursive: true });
  await fsp.copyFile(path.join(fixtures, source), target);
  return target;
}

function git(root, ...args) {
  return execFileSync('git', ['-c', 'commit.gpgsign=false', ...args], { cwd: root, encoding: 'utf8' }).trim();
}

test('committed CycloneDX baseline is read without checkout', async () => {
  const root = await actionWorkspace();
  git(root, 'init');
  git(root, 'config', 'user.email', 'action@example.test');
  git(root, 'config', 'user.name', 'Action Test');
  await copy(root, 'cyclonedx-before.json', 'sboms/application.json');
  git(root, 'add', 'sboms/application.json');
  git(root, 'commit', '-m', 'baseline');
  const baseSHA = git(root, 'rev-parse', 'HEAD');
  await copy(root, 'cyclonedx-after.json', 'sboms/application.json');
  const outputPath = path.join(root, 'runner-temp', 'baseline.json');
  const result = await resolveGitBaseline({
    workspace: root,
    basePath: 'sboms/application.json',
    outputPath,
    env: environment(root),
    event: { pull_request: { base: { sha: baseSHA } } },
  });
  assert.equal(result.firstRun, false);
  assert.match(await fsp.readFile(outputPath, 'utf8'), /lodash@4\.17\.20/);
});

test('SPDX head compares against CycloneDX base and writes SARIF outputs', async () => {
  const root = await actionWorkspace();
  await copy(root, 'spdx-sample.json');
  const result = await runAction(environment(root, { 'INPUT_SARIF': 'true' }), {
    binaryPath: binary,
    event: {},
    resolveBaseline: baselineFrom(path.join(fixtures, 'cyclonedx-before.json')),
  });
  assert.equal(result.verdict, 'pass');
  assert.ok(result.counts.added + result.counts.removed + result.counts.changed > 0);
  assert.equal(JSON.parse(await fsp.readFile(result.paths.sarif, 'utf8')).version, '2.1.0');
  const outputs = await fsp.readFile(path.join(root, 'output.txt'), 'utf8');
  assert.match(outputs, /report-sarif<</);
});

test('a missing baseline is treated as an empty first-run baseline', async () => {
  const root = await actionWorkspace();
  git(root, 'init');
  git(root, 'config', 'user.email', 'action@example.test');
  git(root, 'config', 'user.name', 'Action Test');
  await fsp.writeFile(path.join(root, 'README'), 'first commit');
  git(root, 'add', 'README');
  git(root, 'commit', '-m', 'first');
  const baseSHA = git(root, 'rev-parse', 'HEAD');
  const outputPath = path.join(root, 'runner-temp', 'baseline.json');
  const result = await resolveGitBaseline({
    workspace: root,
    basePath: 'sbom.json',
    outputPath,
    env: environment(root),
    event: { pull_request: { base: { sha: baseSHA } } },
  });
  assert.equal(result.firstRun, true);
  assert.equal(await fsp.readFile(outputPath, 'utf8'), EMPTY_CYCLONEDX);
});

test('forked PR remains useful when comment permission is unavailable', async () => {
  const root = await actionWorkspace();
  await copy(root, 'cyclonedx-after.json');
  const warnings = [];
  const result = await runAction(environment(root, {
    'INPUT_COMMENT': 'true',
    GITHUB_TOKEN: 'read-only-token',
  }), {
    binaryPath: binary,
    event: { number: 42, pull_request: { number: 42 } },
    resolveBaseline: baselineFrom(path.join(fixtures, 'cyclonedx-before.json')),
    upsertComment: async () => { const error = new Error('forbidden'); error.status = 403; throw error; },
    log: { info() {}, warning(message) { warnings.push(message); } },
  });
  assert.equal(result.verdict, 'pass');
  assert.match(warnings.join('\n'), /permission is unavailable/);
  assert.match(await fsp.readFile(path.join(root, 'summary.md'), 'utf8'), /SBOM Diff Report/);
});

test('integrity-drift policy failure sets counts, verdict, and reports before failing', async () => {
  const root = await actionWorkspace();
  await copy(root, 'cyclonedx-integrity-drift.json');
  await fsp.writeFile(path.join(root, 'policy.json'), '{"deny_integrity_drift":true}\n');
  const result = await runAction(environment(root, {
    'INPUT_POLICY': 'policy.json',
    'INPUT_FAIL-ON': 'policy',
  }), {
    binaryPath: binary,
    event: {},
    resolveBaseline: baselineFrom(path.join(fixtures, 'cyclonedx-before.json')),
  });
  assert.equal(result.failed, true);
  assert.equal(result.verdict, 'fail');
  assert.equal(result.counts.integrity, 1);
  assert.equal(result.report.violations.some((item) => item.rule === 'deny_integrity_drift'), true);
});

test('existing Markdown comment is updated instead of duplicated', async () => {
  const calls = [];
  const request = async (method, pathname, token, body) => {
    calls.push({ method, pathname, token, body });
    if (method === 'GET') return [{ id: 99, body: `${COMMENT_MARKER}\nold report`, user: { type: 'Bot' } }];
    return {};
  };
  const operation = await upsertComment({
    repository: 'example/project', issueNumber: 7, token: 'token', markdown: 'new report', request,
  });
  assert.equal(operation, 'updated');
  assert.deepEqual(calls.map((call) => call.method), ['GET', 'PATCH']);
  assert.equal(calls[1].pathname, '/repos/example/project/issues/comments/99');
  assert.match(calls[1].body.body, /new report/);
});

test('repository paths containing spaces are passed safely as process arguments', async () => {
  const root = await actionWorkspace();
  await copy(root, 'spdx-sample.json', 'SBOM files/head document.json');
  const result = await runAction(environment(root, {
    'INPUT_SBOM-PATH': 'SBOM files/head document.json',
    'INPUT_BASE-SBOM-PATH': 'SBOM files/base document.json',
  }), {
    binaryPath: binary,
    event: {},
    resolveBaseline: baselineFrom(path.join(fixtures, 'cyclonedx-before.json')),
  });
  assert.equal(result.verdict, 'pass');
});

test('malformed SBOM input fails closed', async () => {
  const root = await actionWorkspace();
  await copy(root, 'malformed.json');
  await assert.rejects(() => runAction(environment(root), {
    binaryPath: binary,
    event: {},
    resolveBaseline: baselineFrom(path.join(fixtures, 'cyclonedx-before.json')),
  }), /rejected an input|parse/);
});

test('path traversal, symlink escape, oversized input, and unsafe versions are rejected', async () => {
  const root = await actionWorkspace();
  assert.throws(() => relativeRepositoryPath('../secret.json', 'sbom-path'), /traversal/);
  assert.throws(() => relativeRepositoryPath('safe/../secret.json', 'sbom-path'), /traversal/);
  assert.throws(() => relativeRepositoryPath('C:\\secret.json', 'sbom-path'), /repository-relative/);
  const outside = path.join(suiteRoot, 'outside.json');
  await fsp.writeFile(outside, '{}');
  await fsp.symlink(outside, path.join(root, 'escaped.json'));
  await assert.rejects(() => workspaceFile(root, 'escaped.json', 'sbom-path'), /outside/);
  await fsp.writeFile(path.join(root, 'large.json'), '123456');
  await assert.rejects(() => workspaceFile(root, 'large.json', 'sbom-path', 5), /exceeds/);
  assert.throws(() => exactVersion('latest'), /exact release/);
  assert.throws(() => exactVersion('v0.3.7; touch owned'), /exact release/);
});

test('release filenames and checksum selection are exact', () => {
  assert.equal(releaseAsset('v0.3.7', 'linux', 'x64'), 'sbomlyze_0.3.7_Linux_x86_64.tar.gz');
  const hash = 'a'.repeat(64);
  assert.equal(expectedChecksum(`${hash}  sbomlyze_0.3.7_Linux_x86_64.tar.gz\n`, 'sbomlyze_0.3.7_Linux_x86_64.tar.gz'), hash);
  assert.throws(() => expectedChecksum(`${hash}  other.tar.gz\n`, 'wanted.tar.gz'), /does not contain/);
  assert.doesNotThrow(() => validateArchiveListing('LICENSE\nsbomlyze\n', 'sbomlyze'));
  assert.throws(() => validateArchiveListing('../sbomlyze\n', 'sbomlyze'), /unsafe path/);
  assert.throws(() => validateArchiveListing('safe/../sbomlyze\n', 'sbomlyze'), /unsafe path/);
});

test('every fail-on mode has explicit verdict semantics', () => {
  const report = { violations: [{ severity: 'error' }] };
  const changed = { added: 1, removed: 0, changed: 0, integrity: 1 };
  assert.equal(verdictFor('policy', report, changed), 'fail');
  assert.equal(verdictFor('integrity-drift', { violations: [] }, changed), 'fail');
  assert.equal(verdictFor('any-change', { violations: [] }, changed), 'fail');
  assert.equal(verdictFor('never', report, changed), 'pass');
});
