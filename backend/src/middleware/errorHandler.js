/**
 * Central error handler. Never leaks stack traces or internal details to
 * the client in production — verbose errors are a Security Misconfiguration
 * finding category, so the app itself has to avoid it.
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  console.error('[error]', err);

  const isProd = process.env.NODE_ENV === 'production';
  const status = err.status || 500;

  res.status(status).json({
    error: isProd ? 'Something went wrong. Please try again.' : err.message,
    ...(isProd ? {} : { stack: err.stack }),
  });
}

module.exports = { errorHandler };
