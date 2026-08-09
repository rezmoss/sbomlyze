'use strict';

const fsp = require('node:fs/promises');
const fs = require('node:fs');
const dns = require('node:dns/promises');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const zlib = require('node:zlib');
const { apiRequest } = require('./github');

const MAX_BASELINE_BYTES = 50 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024;
const EMPTY_CYCLONEDX = '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}\n';
const GITHUB_DOWNLOAD_HOSTS = new Set([
  'api.github.com', 'github.com', 'objects.githubusercontent.com',
  'release-assets.githubusercontent.com', 'github-releases.githubusercontent.com',
  'pipelines.actions.githubusercontent.com', 'productionresultssa0.blob.core.windows.net',
]);
const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
  return value >>> 0;
});

function repositoryName(value) {
  if (!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(value || '')) throw new Error('baseline-repository must be OWNER/REPO');
  return value;
}

function exactName(value, inputName) {
  if (!value || value === '.' || value === '..' || value.length > 255 || /[\\/\0\r\n]/.test(value) || /[*?\[\]]/.test(value)) {
    throw new Error(`${inputName} must be an exact file or artifact name without paths or glob characters`);
  }
  return value;
}

function safeArchivePath(value, inputName = 'baseline-artifact-path') {
  if (!value || value.includes('\0') || /[\r\n]/.test(value)) throw new Error(`${inputName} must be a non-empty relative path`);
  const portable = value.replace(/\\/g, '/');
  const normalized = path.posix.normalize(portable);
  if (path.posix.isAbsolute(portable) || path.win32.isAbsolute(value) || portable.includes(':') ||
      portable.split('/').includes('..') || normalized === '.' || normalized.startsWith('../')) {
    throw new Error(`${inputName} contains an unsafe path`);
  }
  return normalized.replace(/^\.\//, '');
}

function isPrivateAddress(address) {
  if (net.isIP(address) === 4) {
    const parts = address.split('.').map(Number);
    return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
      (parts[0] === 169 && parts[1] === 254) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) || (parts[0] >= 224);
  }
  if (net.isIP(address) === 6) {
    const lower = address.toLowerCase();
    return lower === '::1' || lower === '::' || lower.startsWith('fc') || lower.startsWith('fd') ||
      /^fe[89ab]/.test(lower) || lower.startsWith('::ffff:127.') || lower.startsWith('::ffff:10.') ||
      lower.startsWith('::ffff:192.168.');
  }
  return false;
}

function publicBaselineURL(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('baseline-url must be a valid HTTPS URL'); }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) {
    throw new Error('baseline-url must be HTTPS without credentials or a non-default port');
  }
  if (!host || net.isIP(host) !== 0 || host.startsWith('::ffff:') || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
      host.endsWith('.internal') || isPrivateAddress(host)) {
    throw new Error('baseline-url must use a public host');
  }
  return url;
}

function allowedGitHubDownloadHost(hostname) {
  return GITHUB_DOWNLOAD_HOSTS.has(hostname) || /^[a-z0-9-]+\.blob\.core\.windows\.net$/.test(hostname);
}

async function streamDownload(urlValue, destination, maxBytes, options = {}, redirects = 0) {
  if (redirects > 5) throw new Error('too many baseline download redirects');
  const url = options.github ? new URL(urlValue) : publicBaselineURL(urlValue);
  if (options.github && (url.protocol !== 'https:' || !allowedGitHubDownloadHost(url.hostname))) {
    throw new Error(`GitHub redirected the baseline download to an untrusted host: ${url.hostname}`);
  }
  const headers = { accept: options.accept || 'application/octet-stream', 'user-agent': 'sbomlyze-action' };
  if (options.token && url.hostname === 'api.github.com') headers.authorization = `Bearer ${options.token}`;
  if (url.hostname === 'api.github.com') headers['x-github-api-version'] = '2022-11-28';

  const requestOptions = { headers };
  if (!options.github) {
    const addresses = await dns.lookup(url.hostname, { all: true, verbatim: true });
    if (addresses.length === 0 || addresses.some((item) => isPrivateAddress(item.address))) {
      throw new Error('baseline-url resolved to a private or unavailable address');
    }
    const selected = addresses[0];
    requestOptions.lookup = (_hostname, _options, callback) => callback(null, selected.address, selected.family);
  }

  await new Promise((resolve, reject) => {
    const request = https.get(url, requestOptions, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        streamDownload(new URL(response.headers.location, url).toString(), destination, maxBytes, options, redirects + 1)
          .then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        const error = new Error(`baseline download returned HTTP ${response.statusCode}`);
        error.status = response.statusCode;
        reject(error);
        return;
      }
      const declared = Number(response.headers['content-length'] || 0);
      if (declared > maxBytes) { response.resume(); reject(new Error(`baseline download exceeds ${maxBytes} bytes`)); return; }
      const output = fs.createWriteStream(destination, { flags: 'wx', mode: 0o600 });
      let received = 0;
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > maxBytes) request.destroy(new Error(`baseline download exceeds ${maxBytes} bytes`));
      });
      response.pipe(output);
      output.on('finish', () => output.close(resolve));
      output.on('error', reject);
      response.on('error', reject);
    });
    request.setTimeout(30_000, () => request.destroy(new Error('baseline download timed out')));
    request.on('error', reject);
  }).catch(async (error) => { await fsp.rm(destination, { force: true }).catch(() => {}); throw error; });
}

function findEndOfCentralDirectory(buffer) {
  const minimum = Math.max(0, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= minimum; offset--) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  throw new Error('workflow artifact is not a valid ZIP archive');
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

async function extractZipEntry(archive, requestedPath, outputPath) {
  const wanted = safeArchivePath(requestedPath);
  const buffer = await fsp.readFile(archive);
  if (buffer.length > MAX_ARTIFACT_BYTES) throw new Error('workflow artifact exceeds the archive size limit');
  const eocd = findEndOfCentralDirectory(buffer);
  const entries = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  let offset = buffer.readUInt32LE(eocd + 16);
  if (entries === 0xffff || centralSize === 0xffffffff || offset === 0xffffffff || offset + centralSize > eocd) {
    throw new Error('ZIP64 or malformed workflow artifacts are not supported');
  }
  let selected;
  for (let index = 0; index < entries; index++) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) throw new Error('malformed ZIP central directory');
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const checksum = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const external = buffer.readUInt32LE(offset + 38);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const end = offset + 46 + nameLength + extraLength + commentLength;
    if (end > buffer.length) throw new Error('malformed ZIP entry');
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString('utf8');
    const normalized = safeArchivePath(name, 'workflow artifact entry');
    if (((external >>> 16) & 0o170000) === 0o120000) throw new Error(`workflow artifact contains a symlink: ${name}`);
    if (normalized === wanted) {
      if (selected) throw new Error(`workflow artifact contains duplicate path: ${wanted}`);
      selected = { flags, method, checksum, compressedSize, uncompressedSize, localOffset };
    }
    offset = end;
  }
  if (!selected) throw new Error(`workflow artifact does not contain ${wanted}`);
  if (selected.flags & 1) throw new Error('encrypted workflow artifact entries are not supported');
  if (![0, 8].includes(selected.method)) throw new Error(`unsupported ZIP compression method ${selected.method}`);
  if (selected.uncompressedSize > MAX_BASELINE_BYTES) throw new Error('baseline SBOM exceeds the 50 MiB limit');
  const local = selected.localOffset;
  if (local + 30 > buffer.length || buffer.readUInt32LE(local) !== 0x04034b50) throw new Error('malformed ZIP local header');
  const dataStart = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
  const dataEnd = dataStart + selected.compressedSize;
  if (dataEnd > buffer.length) throw new Error('truncated ZIP entry');
  const compressed = buffer.subarray(dataStart, dataEnd);
  const content = selected.method === 0 ? Buffer.from(compressed) : zlib.inflateRawSync(compressed, { maxOutputLength: MAX_BASELINE_BYTES + 1 });
  if (content.length !== selected.uncompressedSize || crc32(content) !== selected.checksum) throw new Error('workflow artifact entry failed integrity validation');
  await fsp.writeFile(outputPath, content, { flag: 'wx', mode: 0o600 });
}

async function emptyBaseline(outputPath, provider, source) {
  await fsp.writeFile(outputPath, EMPTY_CYCLONEDX, { flag: 'wx', mode: 0o600 });
  return { firstRun: true, provider, source };
}

async function resolveReleaseBaseline(options) {
  const { repository, assetName, outputPath, token, request = apiRequest, download = streamDownload } = options;
  const repo = repositoryName(repository);
  const asset = exactName(assetName, 'baseline-asset');
  await request('GET', `/repos/${repo}`, token);
  let release;
  try { release = await request('GET', `/repos/${repo}/releases/latest`, token); }
  catch (error) { if (error.status === 404) return emptyBaseline(outputPath, 'release', `${repo}: no release`); throw error; }
  if (!Array.isArray(release.assets)) throw new Error('latest release response did not contain assets');
  const matches = release.assets.filter((item) => item && item.name === asset);
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0].id)) throw new Error(`latest release does not contain exactly one asset named ${asset}`);
  await download(`https://api.github.com/repos/${repo}/releases/assets/${matches[0].id}`, outputPath, MAX_BASELINE_BYTES, {
    github: true, token, accept: 'application/octet-stream',
  });
  return { firstRun: false, provider: 'release', source: `${repo}@${release.tag_name || 'latest'}:${asset}` };
}

async function resolveWorkflowArtifactBaseline(options) {
  const { repository, artifactName, artifactPath, outputPath, archivePath, token,
    request = apiRequest, download = streamDownload, extract = extractZipEntry } = options;
  const repo = repositoryName(repository);
  const name = exactName(artifactName, 'baseline-artifact');
  const inside = safeArchivePath(artifactPath);
  const metadata = await request('GET', `/repos/${repo}`, token);
  if (!metadata || typeof metadata.default_branch !== 'string') throw new Error('repository response did not contain default_branch');
  const query = `branch=${encodeURIComponent(metadata.default_branch)}&status=success&per_page=100`;
  const trustedEvents = new Set(['push', 'workflow_dispatch', 'schedule', 'repository_dispatch', 'release']);
  for (let page = 1; page <= 10; page++) {
    const runsResponse = await request('GET', `/repos/${repo}/actions/runs?${query}&page=${page}`, token);
    if (!Array.isArray(runsResponse.workflow_runs)) throw new Error('workflow runs response was invalid');
    for (const run of runsResponse.workflow_runs) {
      if (!Number.isSafeInteger(run.id) || run.conclusion !== 'success' || run.head_branch !== metadata.default_branch ||
          !trustedEvents.has(run.event)) continue;
      const artifactsResponse = await request('GET', `/repos/${repo}/actions/runs/${run.id}/artifacts?name=${encodeURIComponent(name)}&per_page=100`, token);
      if (!Array.isArray(artifactsResponse.artifacts)) throw new Error('workflow artifacts response was invalid');
      const matches = artifactsResponse.artifacts.filter((item) => item && item.name === name && !item.expired);
      if (matches.length > 1) throw new Error(`successful workflow run ${run.id} contains duplicate ${name} artifacts`);
      if (matches.length === 0) continue;
      if (!Number.isSafeInteger(matches[0].id)) throw new Error('workflow artifact id was invalid');
      await download(`https://api.github.com/repos/${repo}/actions/artifacts/${matches[0].id}/zip`, archivePath, MAX_ARTIFACT_BYTES, {
        github: true, token, accept: 'application/vnd.github+json',
      });
      await extract(archivePath, inside, outputPath);
      return { firstRun: false, provider: 'workflow-artifact', source: `${repo}#${run.id}:${name}/${inside}` };
    }
    if (runsResponse.workflow_runs.length < 100) break;
  }
  return emptyBaseline(outputPath, 'workflow-artifact', `${repo}:${name} (no successful default-branch artifact)`);
}

async function resolveURLBaseline({ url, outputPath, download = streamDownload }) {
  const parsed = publicBaselineURL(url);
  await download(parsed.toString(), outputPath, MAX_BASELINE_BYTES, { github: false });
  return { firstRun: false, provider: 'url', source: parsed.origin };
}

module.exports = {
  EMPTY_CYCLONEDX, GITHUB_DOWNLOAD_HOSTS, MAX_ARTIFACT_BYTES, MAX_BASELINE_BYTES,
  allowedGitHubDownloadHost, crc32, exactName, extractZipEntry, publicBaselineURL, repositoryName,
  resolveReleaseBaseline, resolveURLBaseline, resolveWorkflowArtifactBaseline,
  safeArchivePath, streamDownload,
};
