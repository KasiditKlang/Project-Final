const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token from header

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Token verification failed:', err); // Log error for debugging
            return res.status(403).json({ message: 'Forbidden: Invalid or expired token' });
        }

        req.user = user; // Attach the user data to the request object
        next(); // Proceed to the next middleware or route handler
    });
};

module.exports = authenticateToken;
