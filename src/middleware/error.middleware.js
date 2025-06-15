/**
 * Error Middleware
 * Minimal centralized error handling
 */

const config = require('../config');
const logger = require('../utils/logger');

/**
 * Handle different error types
 */
const getErrorDetails = (error) => {
  // Mongoose validation errors
  if (error.name === 'ValidationError') {
    const errors = Object.values(error.errors).map(err => ({
      field: err.path,
      message: err.message
    }));
    return { status: 400, message: 'Validation failed', errors };
  }

  // Mongoose duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return { 
      status: 409, 
      message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`,
      field 
    };
  }

  // Mongoose cast error (invalid ObjectId)
  if (error.name === 'CastError') {
    return { status: 400, message: 'Invalid ID format' };
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return { status: 401, message: 'Invalid token' };
  }
  if (error.name === 'TokenExpiredError') {
    return { status: 401, message: 'Token expired' };
  }

  // Multer file upload errors
  if (error.code === 'LIMIT_FILE_SIZE') {
    return { status: 400, message: 'File too large' };
  }
  if (error.code === 'LIMIT_FILE_COUNT') {
    return { status: 400, message: 'Too many files' };
  }

  // Default server error
  return { 
    status: error.status || 500, 
    message: error.message || 'Internal server error' 
  };
};

/**
 * Main error handler
 */
const handleError = () => {
  return (error, req, res, next) => {
    const { status, message, errors, field } = getErrorDetails(error);

    // Log error details
    if (status >= 500) {
      logger.error('Server Error', error, {
        url: req.originalUrl,
        method: req.method,
        userId: req.user?.id,
        ip: req.ip
      });
    } else {
      logger.warn('Client Error', { message, status, url: req.originalUrl });
    }

    // Send error response
    const response = {
      success: false,
      message,
      ...(errors && { errors }),
      ...(field && { field }),
      ...(config.isDevelopment() && { stack: error.stack })
    };

    res.status(status).json(response);
  };
};

/**
 * Handle 404 errors
 */
const handle404 = () => {
  return (req, res) => {
    logger.warn('Route not found', {
      url: req.originalUrl,
      method: req.method,
      ip: req.ip
    });

    res.status(404).json({
      success: false,
      message: 'Route not found',
      path: req.originalUrl
    });
  };
};

module.exports = {
  handleError,
  handle404
};