/**
 * Central error handler. Never leaks stack traces or internal details to
 * the client in production — verbose errors are a Security Misconfiguration
 * finding category, so the app itself has to avoid it.
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  const isProd = process.env.NODE_ENV === 'production';

  // Keep production logs useful without serializing the entire error object,
  // which can accidentally include request/configuration data or large stacks.
  if (isProd) {
    console.error('[error]', err?.message || 'Unhandled application error');
  } else {
    console.error('[error]', err);
  }

  const candidateStatus = Number(err?.status);
  const status = Number.isInteger(candidateStatus) && candidateStatus >= 400 && candidateStatus < 600
    ? candidateStatus
    : 500;

  if (res.headersSent) return next(err);

  res.status(status).json({
    error: isProd ? 'Something went wrong. Please try again.' : err?.message || 'Internal server error',
    ...(isProd ? {} : { stack: err?.stack }),
  });
}

module.exports = { errorHandler };
