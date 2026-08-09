'use strict';

const { spawn } = require('node:child_process');

const MAX_COMMAND_OUTPUT = 128 * 1024 * 1024;

function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env || process.env,
      windowsHide: true,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let stdoutSize = 0;
    let stderrSize = 0;
    let outputError;
    const timeout = setTimeout(() => {
      outputError = new Error(`${command} exceeded its time limit`);
      child.kill();
    }, options.timeoutMs || 5 * 60 * 1000);
    timeout.unref();

    const collect = (target, isStdout) => (chunk) => {
      if (outputError) return;
      if (isStdout) stdoutSize += chunk.length;
      else stderrSize += chunk.length;
      if (stdoutSize + stderrSize > (options.maxOutput || MAX_COMMAND_OUTPUT)) {
        outputError = new Error(`${command} produced too much output`);
        child.kill();
        return;
      }
      target.push(chunk);
    };
    child.stdout.on('data', collect(stdout, true));
    child.stderr.on('data', collect(stderr, false));
    child.on('error', reject);
    child.on('close', (code, signal) => {
      clearTimeout(timeout);
      if (outputError) return reject(outputError);
      resolve({
        code: code === null ? 1 : code,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
  });
}

module.exports = { runProcess };
