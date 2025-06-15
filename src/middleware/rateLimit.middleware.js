/**
 * Rate Limiting Middleware
 * Minimal Redis-based rate limiting
 */

const rateLimit = require('express-rate-limit');
const { cache } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Redis store for rate limiting
 */
const redisStore = {
  async incr(key) {
    try {
      const count = await cache.incr(key, 900); // 15 minutes TTL
      return { totalHits: count, resetTime: new Date(Date.now() + 900000) };
    } catch (error) {
      logger.error('Rate limit store error', error);
      return { totalHits: 1, resetTime: new Date(Date.now() + 900000) };
    }
  },
  
  async decrement(key) {
    try {
      await cache.del(key);
    } catch (error) {
      logger.error('Rate limit decrement error', error);
    }
  },
  
  async resetKey(key) {
    try {
      await cache.del(key);
    } catch (error) {
      logger.error('Rate limit reset error', error);
    }
  }
};

/**
 * Standard rate limit handler
 */
const onLimitReached = (req, res, options) => {
  logger.security('Rate limit exceeded', {
    ip: req.ip,
    url: req.originalUrl,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });
};

/**
 * General API rate limit
 */
const createRateLimit = () => {
  return rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `rate_limit:${req.ip}`,
    store: redisStore,
    onLimitReached,
    message: {
      success: false,
      message: config.rateLimit.message,
      retryAfter: Math.ceil(config.rateLimit.windowMs / 1000)
    }
  });
};

/**
 * Strict auth endpoint rate limit
 */
const createAuthRateLimit = () => {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `auth_limit:${req.ip}`,
    store: redisStore,
    onLimitReached,
    message: {
      success: false,
      message: 'Too many authentication attempts. Please try again later.',
      retryAfter: 900
    }
  });
};

/**
 * Authenticated user rate limit (higher limits)
 */
const createAuthenticatedRateLimit = () => {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Higher limit for authenticated users
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `auth_user_limit:${req.user?.id || req.ip}`,
    store: redisStore,
    skip: (req) => !req.user, // Skip if not authenticated
    onLimitReached,
    message: {
      success: false,
      message: 'Rate limit exceeded for authenticated requests.',
      retryAfter: 900
    }
  });
};

/**
 * File upload rate limit
 */
const createUploadRateLimit = () => {
  return rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // 20 uploads per hour
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `upload_limit:${req.user?.id || req.ip}`,
    store: redisStore,
    onLimitReached,
    message: {
      success: false,
      message: 'Upload limit exceeded. Please try again later.',
      retryAfter: 3600
    }
  });
};

module.exports = {
  createRateLimit,
  createAuthRateLimit,
  createAuthenticatedRateLimit,
  createUploadRateLimit
};