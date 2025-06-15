/**
 * Express Application Setup
 * Main application configuration with middleware, routes, and error handling
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const path = require('path');

// Import configuration and utilities
const config = require('./config');
const logger = require('./utils/logger');

// Import middleware
const authMiddleware = require('./middleware/auth.middleware');
const validationMiddleware = require('./middleware/validation.middleware');
const errorMiddleware = require('./middleware/error.middleware');
const rateLimitMiddleware = require('./middleware/rateLimit.middleware');

// Import routes
const routes = require('./routes');

/**
 * Create Express application
 */
const app = express();

/**
 * Trust proxy for accurate IP addresses
 */
app.set('trust proxy', 1);

/**
 * Security Middleware
 * Applied before other middleware for maximum protection
 */

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors(config.cors));

// MongoDB injection prevention
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    logger.security('MongoDB injection attempt detected', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      key,
      url: req.url
    });
  }
}));

/**
 * Request Processing Middleware
 */

// Enable compression
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Body parsing middleware
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    // Store raw body for webhook verification if needed
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
if (config.logging.enableRequestLogging) {
  app.use(logger.createRequestLogger());
}

/**
 * Rate Limiting
 */
app.use(rateLimitMiddleware.createRateLimit());

// Stricter rate limiting for auth endpoints
app.use('/api/*/auth', rateLimitMiddleware.createAuthRateLimit());

/**
 * Static Files & Health Checks
 */

// Serve uploaded files
app.use('/uploads', express.static(config.upload.uploadPath, {
  maxAge: '1d',
  etag: true,
  lastModified: true
}));

// Health check endpoint (before auth)
app.get('/health', async (req, res) => {
  try {
    const { healthCheck: dbHealth } = require('./config/database');
    const { healthCheck: redisHealth } = require('./config/redis');

    const [database, redis] = await Promise.all([
      dbHealth(),
      redisHealth()
    ]);

    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: config.nodeEnv,
      version: process.env.npm_package_version || '1.0.0',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      services: {
        database,
        redis
      }
    };

    // Overall health status
    const allHealthy = database.status === 'healthy' && redis.status === 'healthy';
    
    if (!allHealthy) {
      health.status = 'degraded';
      return res.status(503).json(health);
    }

    res.json(health);
  } catch (error) {
    logger.error('Health check failed', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// Ready check for Kubernetes
app.get('/ready', (req, res) => {
  res.status(200).json({ status: 'ready' });
});

// Live check for Kubernetes
app.get('/live', (req, res) => {
  res.status(200).json({ status: 'alive' });
});

/**
 * API Documentation
 */
if (config.docs.enabled) {
  const swaggerUi = require('swagger-ui-express');
  const swaggerDocument = require('../docs/swagger.json');
  
  app.use(config.docs.path, swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: config.docs.title
  }));

  logger.info(`📚 API Documentation available at ${config.docs.path}`);
}

/**
 * Request ID Middleware
 */
app.use((req, res, next) => {
  req.id = require('uuid').v4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

/**
 * API Routes
 */
app.use(`/api/${config.apiVersion}`, routes);

/**
 * Root endpoint
 */
app.get('/', (req, res) => {
  res.json({
    name: 'Task Management API',
    version: process.env.npm_package_version || '1.0.0',
    environment: config.nodeEnv,
    documentation: config.docs.enabled ? `${req.protocol}://${req.get('host')}${config.docs.path}` : null,
    health: `${req.protocol}://${req.get('host')}/health`,
    timestamp: new Date().toISOString()
  });
});

/**
 * 404 Handler
 */
app.use('*', (req, res) => {
  logger.warn('Route not found', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

/**
 * Error Handling Middleware
 * Must be last in the middleware stack
 */
app.use(logger.errorLogger());
app.use(errorMiddleware.handleError());

/**
 * Global error handlers for uncaught errors
 */
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', error);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', new Error(reason), { promise });
});

/**
 * Graceful shutdown handling
 */
function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  
  // Close server and cleanup resources
  // This will be handled by server.js
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

/**
 * Development-only middleware
 */
if (config.isDevelopment()) {
  // Enable detailed error messages
  app.locals.pretty = true;
  
  // Add development headers
  app.use((req, res, next) => {
    res.setHeader('X-Development-Mode', 'true');
    next();
  });
  
  logger.info('🔧 Development mode enabled');
}

/**
 * Production optimizations
 */
if (config.isProduction()) {
  // Remove Express header
  app.disable('x-powered-by');
  
  // Enable view cache
  app.enable('view cache');
  
  logger.info('🚀 Production optimizations enabled');
}

/**
 * Application startup logging
 */
logger.startup(
  'Task Management API',
  process.env.npm_package_version || '1.0.0',
  config.port
);

module.exports = app;