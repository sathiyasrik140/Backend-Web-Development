const jwt = require('jsonwebtoken');

const AUTH_REQUIRED_BODY = {
  error: {
    code: 'AUTH_REQUIRED',
    message: 'Authentication required',
  },
};

function sendUnauthorized(res) {
  return res.status(401).json(AUTH_REQUIRED_BODY);
}

/**
 * Verify a Bearer JWT from the Authorization header and attach decoded claims to req.user.
 */
module.exports = function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization ?? '';
  const match = /^Bearer ([^\s]+)$/i.exec(authHeader);
  const token = match ? match[1] : null;

  if (!token) {
    return sendUnauthorized(res);
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
    });
    req.user = payload;
    return next();
  } catch (_error) {
    return sendUnauthorized(res);
  }
};
