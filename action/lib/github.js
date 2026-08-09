'use strict';

const https = require('node:https');

const COMMENT_MARKER = '<!-- sbomlyze-action-report -->';
const MAX_COMMENT_CHARS = 60_000;

function apiRequest(method, pathname, token, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const request = https.request({
      protocol: 'https:',
      hostname: 'api.github.com',
      method,
      path: pathname,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'sbomlyze-action',
        'x-github-api-version': '2022-11-28',
        ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}),
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) request.destroy(new Error('GitHub API response was too large'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed;
        try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
        if (response.statusCode < 200 || response.statusCode >= 300) {
          const error = new Error(`GitHub API ${method} ${pathname} returned ${response.statusCode}`);
          error.status = response.statusCode;
          error.response = parsed;
          reject(error);
          return;
        }
        resolve(parsed);
      });
      response.on('error', reject);
    });
    request.setTimeout(30_000, () => request.destroy(new Error('GitHub API request timed out')));
    request.on('error', reject);
    if (data) request.write(data);
    request.end();
  });
}

function commentBody(markdown) {
  if (markdown.length <= MAX_COMMENT_CHARS) return `${COMMENT_MARKER}\n${markdown}`;
  return `${COMMENT_MARKER}\n${markdown.slice(0, MAX_COMMENT_CHARS)}\n\n_Report truncated; use the report-markdown output for the complete report._`;
}

async function upsertComment({ repository, issueNumber, token, markdown, request = apiRequest }) {
  if (!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository)) throw new Error('invalid GITHUB_REPOSITORY');
  if (!Number.isSafeInteger(issueNumber) || issueNumber <= 0) throw new Error('invalid pull request number');
  const base = `/repos/${repository}`;
  let previous;
  for (let page = 1; page <= 10 && !previous; page++) {
    const comments = await request('GET', `${base}/issues/${issueNumber}/comments?per_page=100&page=${page}`, token);
    if (!Array.isArray(comments)) throw new Error('GitHub comments response was not an array');
    previous = comments.find((comment) =>
      typeof comment.body === 'string' && comment.body.includes(COMMENT_MARKER) &&
      (comment.user?.type === 'Bot' || comment.user?.login === 'github-actions[bot]'));
    if (comments.length < 100) break;
  }
  const body = { body: commentBody(markdown) };
  if (previous) {
    if (!Number.isSafeInteger(previous.id) || previous.id <= 0) throw new Error('GitHub comment id was invalid');
    await request('PATCH', `${base}/issues/comments/${previous.id}`, token, body);
    return 'updated';
  }
  await request('POST', `${base}/issues/${issueNumber}/comments`, token, body);
  return 'created';
}

module.exports = { COMMENT_MARKER, apiRequest, commentBody, upsertComment };
