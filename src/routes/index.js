/**
 * API Routes Index
 * Central routing configuration for all API endpoints
 */

const express = require('express');
const config = require('../config');
const logger = require('../utils/logger');

// Import route modules
const authRoutes = require('./auth.routes');
const userRoutes = require('./user.routes');
const taskRoutes = require('./task.routes');

// Import middleware
const authMiddleware = require('../middleware/auth.middleware');
const validationMiddleware = require('../middleware/validation.middleware');

/**
 * Create main router
 */
const router = express.Router();

/**
 * API Information Endpoint
 */
router.get('/', (req, res) => {
  res.json({
    name: 'Task Management API',
    version: config.apiVersion,
    environment: config.nodeEnv,
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: {
        base: '/auth',
        description: 'Authentication and authorization endpoints',
        routes: [
          'POST /auth/register - User registration',
          'POST /auth/login - User login',
          'POST /auth/refresh - Refresh access token',
          'POST /auth/logout - User logout',
          'POST /auth/forgot-password - Request password reset',
          'POST /auth/reset-password - Reset password with token',
          'GET /auth/me - Get current user profile'
        ]
      },
      users: {
        base: '/users',
        description: 'User management endpoints',
        authentication: 'Required',
        routes: [
          'GET /users - Get all users (admin only)',
          'GET /users/:id - Get user by ID',
          'PUT /users/:id - Update user',
          'DELETE /users/:id - Delete user',
          'PUT /users/:id/avatar - Update user avatar',
          'GET /users/:id/tasks - Get user tasks'
        ]
      },
      tasks: {
        base: '/tasks',
        description: 'Task management endpoints',
        authentication: 'Required',
        routes: [
          'GET /tasks - Get tasks with filtering and pagination',
          'POST /tasks - Create new task',
          'GET /tasks/:id - Get task by ID',
          'PUT /tasks/:id - Update task',
          'DELETE /tasks/:id - Delete task',
          'PUT /tasks/:id/status - Update task status',
          'POST /tasks/:id/comments - Add comment to task',
          'GET /tasks/:id/comments - Get task comments',
          'POST /tasks/:id/attachments - Add attachment to task',
          'GET /tasks/:id/attachments - Get task attachments'
        ]
      }
    },
    features: {
      authentication: 'JWT with refresh tokens',
      authorization: 'Role-based access control',
      validation: 'Request/response validation with Joi',
      caching: 'Redis-based caching',
      realtime: 'WebSocket notifications',
      fileUpload: 'Support for task attachments',
      rateLimit: 'IP-based rate limiting',
      logging: 'Structured logging with correlation IDs'
    },
    documentation: config.docs.enabled ? `${req.protocol}://${req.get('host')}${config.docs.path}` : 'Disabled',
    healthCheck: `${req.protocol}://${req.get('host')}/health`
  });
});

/**
 * API Status Endpoint
 */
router.get('/status', async (req, res) => {
  try {
    const { getConnectionStatus: dbStatus } = require('../config/database');
    const { getConnectionStatus: redisStatus } = require('../config/redis');
    
    const status = {
      api: 'operational',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
      },
      services: {
        database: dbStatus(),
        redis: redisStatus()
      },
      environment: {
        node: process.version,
        platform: process.platform,
        environment: config.nodeEnv
      }
    };

    res.json(status);
  } catch (error) {
    logger.error('Failed to get API status', error);
    res.status(500).json({
      api: 'error',
      timestamp: new Date().toISOString(),
      error: 'Failed to retrieve status information'
    });
  }
});

/**
 * Request validation middleware for all routes
 */
router.use(validationMiddleware.validateRequest());

/**
 * Authentication Routes
 * Public routes that don't require authentication
 */
router.use('/auth', authRoutes);

/**
 * Rate limiting middleware for authenticated routes
 */
const authenticatedRateLimit = require('../middleware/rateLimit.middleware').createAuthenticatedRateLimit();
router.use(authenticatedRateLimit);

/**
 * Authentication middleware for protected routes
 * All routes below this point require valid JWT token
 */
router.use(authMiddleware.authenticate());

/**
 * User Routes
 * Protected routes for user management
 */
router.use('/users', userRoutes);

/**
 * Task Routes  
 * Protected routes for task management
 */
router.use('/tasks', taskRoutes);

/**
 * Admin Routes
 * Routes that require admin privileges
 */
router.use('/admin', authMiddleware.requireRole(['admin']), (req, res) => {
  res.json({
    message: 'Admin routes placeholder',
    availableEndpoints: [
      'GET /admin/users - Manage all users',
      'GET /admin/tasks - View all tasks',
      'GET /admin/analytics - System analytics',
      'POST /admin/maintenance - Trigger maintenance tasks'
    ]
  });
});

/**
 * Development Routes
 * Only available in development environment
 */
if (config.isDevelopment()) {
  router.use('/dev', require('./dev.routes'));
  logger.info('🔧 Development routes enabled');
}

/**
 * API Metrics Endpoint
 * Provides basic API metrics
 */
router.get('/metrics', authMiddleware.requireRole(['admin']), async (req, res) => {
  try {
    const { getDatabaseStats } = require('../config/database');
    const { getRedisStats } = require('../config/redis');

    const metrics = {
      timestamp: new Date().toISOString(),
      api: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage()
      },
      database: await getDatabaseStats(),
      cache: await getRedisStats()
    };

    res.json(metrics);
  } catch (error) {
    logger.error('Failed to get API metrics', error);
    res.status(500).json({
      error: 'Failed to retrieve metrics',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * API Version Compatibility
 * Handle requests to older API versions
 */
router.use('/v*', (req, res) => {
  const requestedVersion = req.path.split('/')[1];
  
  logger.warn('Deprecated API version requested', {
    requestedVersion,
    currentVersion: config.apiVersion,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(410).json({
    error: 'API version no longer supported',
    requestedVersion,
    currentVersion: config.apiVersion,
    message: `Please upgrade to /api/${config.apiVersion}`,
    migrationGuide: config.docs.enabled ? `${req.protocol}://${req.get('host')}${config.docs.path}` : null
  });
});

/**
 * Catch-all for undefined API routes
 */
router.use('*', (req, res) => {
  logger.warn('Unknown API endpoint accessed', {
    method: req.method,
    path: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    method: req.method,
    path: req.originalUrl,
    availableEndpoints: {
      auth: '/auth',
      users: '/users',
      tasks: '/tasks',
      status: '/status',
      documentation: config.docs.enabled ? config.docs.path : null
    },
    timestamp: new Date().toISOString()
  });
});

/**
 * Route-level error handler
 */
router.use((error, req, res, next) => {
  logger.error('Route-level error', error, {
    method: req.method,
    path: req.originalUrl,
    ip: req.ip
  });

  // Pass error to global error handler
  next(error);
});

module.exports = router;