'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const https = require('node:https');
const path = require('node:path');
const { runProcess } = require('./process');

const REPOSITORY = 'rezmoss/sbomlyze';
const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;
const MAX_CHECKSUM_BYTES = 1024 * 1024;
const ALLOWED_DOWNLOAD_HOSTS = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'github-releases.githubusercontent.com',
]);

function exactVersion(value) {
  const version = value.trim();
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`version must be an exact release such as v0.3.7; received ${JSON.stringify(value)}`);
  }
  return version;
}

function releaseAsset(version, platform = process.platform, arch = process.arch) {
  const number = version.slice(1);
  const osNames = { linux: 'Linux', darwin: 'Darwin', win32: 'Windows' };
  const archNames = { x64: 'x86_64', arm64: 'arm64', ia32: 'i386' };
  const osName = osNames[platform];
  const archName = archNames[arch];
  if (!osName || !archName || (platform === 'win32' && arch !== 'x64')) {
    throw new Error(`unsupported runner platform: ${platform}/${arch}`);
  }
  const extension = platform === 'win32' ? 'zip' : 'tar.gz';
  return `sbomlyze_${number}_${osName}_${archName}.${extension}`;
}

function allowedDownloadURL(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || !ALLOWED_DOWNLOAD_HOSTS.has(url.hostname)) {
    throw new Error(`refusing download from untrusted host ${url.hostname || value}`);
  }
  return url;
}

async function download(urlValue, destination, maxBytes, redirects = 0) {
  const url = allowedDownloadURL(urlValue);
  if (redirects > 5) throw new Error('too many release download redirects');

  await new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { 'user-agent': 'sbomlyze-action' } }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        download(new URL(response.headers.location, url).toString(), destination, maxBytes, redirects + 1)
          .then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`download failed with HTTP ${response.statusCode}: ${url}`));
        return;
      }
      const declared = Number(response.headers['content-length'] || 0);
      if (declared > maxBytes) {
        response.resume();
        reject(new Error(`download exceeds ${maxBytes} bytes: ${url}`));
        return;
      }
      const stream = fs.createWriteStream(destination, { flags: 'wx', mode: 0o600 });
      let received = 0;
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > maxBytes) {
          request.destroy(new Error(`download exceeds ${maxBytes} bytes: ${url}`));
        }
      });
      response.pipe(stream);
      stream.on('finish', () => stream.close(resolve));
      stream.on('error', reject);
      response.on('error', reject);
    });
    request.setTimeout(30_000, () => request.destroy(new Error(`download timed out: ${url}`)));
    request.on('error', reject);
  });
}

async function sha256(filename) {
  const hash = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filename);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  return hash.digest('hex');
}

function expectedChecksum(contents, asset) {
  for (const line of contents.split(/\r?\n/)) {
    const match = line.match(/^([0-9a-fA-F]{64}) [ *](.+)$/);
    if (match && match[2] === asset) return match[1].toLowerCase();
  }
  throw new Error(`checksums.txt does not contain ${asset}`);
}

function validateArchiveListing(contents, binaryName) {
  const entries = contents.split(/\r?\n/).filter(Boolean);
  for (const entry of entries) {
    const portable = entry.replace(/\\/g, '/');
    const normalized = path.posix.normalize(portable);
    if (path.posix.isAbsolute(portable) || path.win32.isAbsolute(entry) ||
        portable.split('/').includes('..') || normalized === '..' ||
        normalized.startsWith('../') || portable.includes(':')) {
      throw new Error(`release archive contains an unsafe path: ${entry}`);
    }
  }
  if (!entries.includes(binaryName)) throw new Error(`release archive does not contain ${binaryName}`);
}

async function verifyProvenance(archive, env, log) {
  let support;
  try {
    support = await runProcess('gh', ['attestation', '--help'], { env, maxOutput: 1024 * 1024 });
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      log.warning('GitHub CLI is unavailable; checksum passed but provenance verification was skipped.');
      return false;
    }
    throw error;
  }
  if (support.code !== 0) {
    log.warning('GitHub CLI lacks attestation support; checksum passed but provenance verification was skipped.');
    return false;
  }

  const result = await runProcess('gh', [
    'attestation', 'verify', archive,
    '--repo', REPOSITORY,
    '--signer-workflow', `${REPOSITORY}/.github/workflows/release.yml`,
  ], { env, maxOutput: 4 * 1024 * 1024 });
  if (result.code !== 0) {
    throw new Error(`release provenance verification failed: ${result.stderr.trim() || result.stdout.trim()}`);
  }
  log.info('Verified GitHub artifact provenance.');
  return true;
}

async function installBinary(versionValue, directory, env, log) {
  const version = exactVersion(versionValue);
  const asset = releaseAsset(version);
  const releaseBase = `https://github.com/${REPOSITORY}/releases/download/${encodeURIComponent(version)}`;
  const archive = path.join(directory, asset);
  const checksums = path.join(directory, 'checksums.txt');
  await download(`${releaseBase}/${encodeURIComponent(asset)}`, archive, MAX_ARCHIVE_BYTES);
  await download(`${releaseBase}/checksums.txt`, checksums, MAX_CHECKSUM_BYTES);

  const checksumContents = await fsp.readFile(checksums, 'utf8');
  const expected = expectedChecksum(checksumContents, asset);
  const actual = await sha256(archive);
  if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex'))) {
    throw new Error(`checksum mismatch for ${asset}`);
  }
  log.info(`Verified SHA-256 checksum for ${asset}.`);
  await verifyProvenance(archive, env, log);

  const extracted = path.join(directory, 'bin');
  await fsp.mkdir(extracted, { mode: 0o700 });
  const listArgs = asset.endsWith('.zip') ? ['-tf', archive] : ['-tzf', archive];
  const listing = await runProcess('tar', listArgs, { env, maxOutput: 4 * 1024 * 1024 });
  if (listing.code !== 0) throw new Error(`could not inspect ${asset}: ${listing.stderr.trim()}`);
  const binaryName = process.platform === 'win32' ? 'sbomlyze.exe' : 'sbomlyze';
  validateArchiveListing(listing.stdout, binaryName);
  const args = asset.endsWith('.zip')
    ? ['-xf', archive, '-C', extracted, binaryName]
    : ['-xzf', archive, '-C', extracted, binaryName];
  const extraction = await runProcess('tar', args, { env, maxOutput: 4 * 1024 * 1024 });
  if (extraction.code !== 0) throw new Error(`could not extract ${asset}: ${extraction.stderr.trim()}`);
  const binary = path.join(extracted, binaryName);
  const stat = await fsp.lstat(binary).catch(() => null);
  if (!stat || !stat.isFile()) throw new Error(`release archive does not contain the sbomlyze binary`);
  if (process.platform !== 'win32') await fsp.chmod(binary, 0o700);
  return binary;
}

module.exports = {
  ALLOWED_DOWNLOAD_HOSTS,
  exactVersion,
  expectedChecksum,
  installBinary,
  releaseAsset,
  sha256,
  validateArchiveListing,
};
