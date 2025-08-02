const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('No token provided in request');
    return res.status(401).json({ error: 'Access denied: No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    console.log('Token verified, user:', user);
    next();
  });
};

// Middleware to restrict to admin
const restrictToAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    console.log('Access denied: User is not admin, role:', req.user.role);
    return res.status(403).json({ error: 'Access restricted to admins' });
  }
  next();
};

// Middleware to restrict to specific roles
const restrictToRoles = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    console.log(`Access denied: User role ${req.user.role} not in allowed roles: ${roles}`);
    return res.status(403).json({ error: `Access restricted to ${roles.join(' or ')}` });
  }
  next();
};

module.exports = { authenticateToken, restrictToAdmin, restrictToRoles };