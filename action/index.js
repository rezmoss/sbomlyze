'use strict';

const { runAction, emitError } = require('./lib/action');

runAction(process.env)
  .then((result) => {
    if (result.failed) {
      emitError(result.message);
      process.exitCode = 1;
    }
  })
  .catch((error) => {
    emitError(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
