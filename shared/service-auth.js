const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'praktikum-zero-trust-secret';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'praktikum-gateway-secret';

function verifyGatewayAndToken(req, res, next) {
  if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) return res.status(401).json({ error: 'Gateway secret tidak valid' });
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!raw) return res.status(401).json({ error: 'Token wajib disertakan' });
  try {
    req.auth = jwt.verify(raw, JWT_SECRET);
    next();
  } catch (_) {
    res.status(401).json({ error: 'Token tidak valid atau kedaluwarsa' });
  }
}

module.exports = { verifyGatewayAndToken, JWT_SECRET, GATEWAY_SECRET };
