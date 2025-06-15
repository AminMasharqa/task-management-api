/**
 * Authentication Middleware
 * JWT validation, role checking, ownership verification, and security
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Task = require('../models/Task');
const authService = require('../services/auth.service');
const { cache } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Extract token from request headers
 */
const extractToken = (req) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }
  
  // Check for token in query parameters (for WebSocket or special cases)
  if (req.query.token) {
    return req.query.token;
  }
  
  // Check for token in cookies (if using cookie-based auth)
  if (req.cookies && req.cookies.accessToken) {
    return req.cookies.accessToken;
  }
  
  return null;
};

/**
 * Main authentication middleware
 * Validates JWT token and attaches user to request
 */
const authenticate = (options = {}) => {
  return async (req, res, next) => {
    try {
      const token = extractToken(req);
      
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Access token is required',
          error: 'MISSING_TOKEN'
        });
      }

      // Verify token using auth service
      const decoded = await authService.verifyToken(token, 'access');
      
      // Check if user still exists and is active
      const user = await User.findById(decoded.userId)
        .select('firstName lastName email username role isActive emailVerified lastLoginAt tokenVersion')
        .lean();

      if (!user) {
        logger.security('Token used for non-existent user', {
          userId: decoded.userId,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        return res.status(401).json({
          success: false,
          message: 'User not found',
          error: 'USER_NOT_FOUND'
        });
      }

      if (!user.isActive) {
        logger.security('Token used for inactive user', {
          userId: user._id,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        return res.status(403).json({
          success: false,
          message: 'Account is deactivated',
          error: 'ACCOUNT_INACTIVE'
        });
      }

      // Check email verification if required
      if (options.requireEmailVerification && !user.emailVerified) {
        return res.status(403).json({
          success: false,
          message: 'Email verification required',
          error: 'EMAIL_NOT_VERIFIED'
        });
      }

      // Attach user to request
      req.user = {
        id: user._id.toString(),
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        username: user.username,
        role: user.role,
        emailVerified: user.emailVerified,
        lastLoginAt: user.lastLoginAt
      };

      // Set global context for logging
      global.userId = req.user.id;

      // Update session if session ID provided
      const sessionId = req.headers['x-session-id'];
      if (sessionId) {
        await authService.updateSessionAccess(req.user.id, sessionId);
      }

      // Cache user data for performance
      await cache.set(`user:${req.user.id}`, req.user, 300); // 5 minutes

      logger.debug('User authenticated successfully', {
        userId: req.user.id,
        role: req.user.role,
        endpoint: req.path
      });

      next();

    } catch (error) {
      logger.security('Authentication failed', error, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.path
      });

      // Handle specific JWT errors
      if (error.message.includes('expired')) {
        return res.status(401).json({
          success: false,
          message: 'Access token has expired',
          error: 'TOKEN_EXPIRED'
        });
      }

      if (error.message.includes('invalid') || error.message.includes('malformed')) {
        return res.status(401).json({
          success: false,
          message: 'Invalid access token',
          error: 'INVALID_TOKEN'
        });
      }

      if (error.message.includes('revoked')) {
        return res.status(401).json({
          success: false,
          message: 'Access token has been revoked',
          error: 'TOKEN_REVOKED'
        });
      }

      if (error.message.includes('version mismatch')) {
        return res.status(401).json({
          success: false,
          message: 'Please login again',
          error: 'TOKEN_VERSION_MISMATCH'
        });
      }

      return res.status(401).json({
        success: false,
        message: 'Authentication failed',
        error: 'AUTH_FAILED'
      });
    }
  };
};

/**
 * Optional authentication middleware
 * Attaches user if token is valid, but doesn't fail if missing
 */
const optionalAuth = () => {
  return async (req, res, next) => {
    try {
      const token = extractToken(req);
      
      if (!token) {
        return next(); // Continue without authentication
      }

      // Try to verify token
      const decoded = await authService.verifyToken(token, 'access');
      const user = await User.findById(decoded.userId)
        .select('firstName lastName email username role isActive emailVerified')
        .lean();

      if (user && user.isActive) {
        req.user = {
          id: user._id.toString(),
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          username: user.username,
          role: user.role,
          emailVerified: user.emailVerified
        };
        
        global.userId = req.user.id;
      }

      next();

    } catch (error) {
      // Silently continue without authentication
      logger.debug('Optional authentication failed', error);
      next();
    }
  };
};

/**
 * Role-based authorization middleware
 */
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        error: 'NOT_AUTHENTICATED'
      });
    }

    const userRole = req.user.role;
    const allowedRoles = Array.isArray(roles) ? roles : [roles];

    if (!allowedRoles.includes(userRole)) {
      logger.security('Insufficient permissions', {
        userId: req.user.id,
        userRole,
        requiredRoles: allowedRoles,
        endpoint: req.path,
        ip: req.ip
      });

      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        error: 'INSUFFICIENT_PERMISSIONS',
        required: allowedRoles,
        current: userRole
      });
    }

    logger.debug('Role authorization successful', {
      userId: req.user.id,
      role: userRole,
      endpoint: req.path
    });

    next();
  };
};

/**
 * Resource ownership verification
 */
const requireOwnership = (options = {}) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          error: 'NOT_AUTHENTICATED'
        });
      }

      const { resourceParam = 'id', resourceType = 'user' } = options;
      const resourceId = req.params[resourceParam];
      const userId = req.user.id;

      // For user resources, check if user is accessing their own data
      if (resourceType === 'user') {
        if (resourceId !== userId) {
          logger.security('Ownership violation attempt', {
            userId,
            resourceId,
            resourceType,
            endpoint: req.path,
            ip: req.ip
          });

          return res.status(403).json({
            success: false,
            message: 'You can only access your own resources',
            error: 'OWNERSHIP_VIOLATION'
          });
        }
      }

      // For other resources, check ownership in database
      else {
        let resource;
        
        switch (resourceType) {
          case 'task':
            resource = await Task.findById(resourceId).select('createdBy').lean();
            break;
          default:
            return res.status(400).json({
              success: false,
              message: 'Invalid resource type',
              error: 'INVALID_RESOURCE_TYPE'
            });
        }

        if (!resource) {
          return res.status(404).json({
            success: false,
            message: `${resourceType.charAt(0).toUpperCase() + resourceType.slice(1)} not found`,
            error: 'RESOURCE_NOT_FOUND'
          });
        }

        if (resource.createdBy.toString() !== userId) {
          logger.security('Resource ownership violation', {
            userId,
            resourceId,
            resourceType,
            ownerId: resource.createdBy,
            endpoint: req.path,
            ip: req.ip
          });

          return res.status(403).json({
            success: false,
            message: 'You do not own this resource',
            error: 'NOT_RESOURCE_OWNER'
          });
        }
      }

      logger.debug('Ownership verification successful', {
        userId,
        resourceId,
        resourceType,
        endpoint: req.path
      });

      next();

    } catch (error) {
      logger.error('Ownership verification failed', error, {
        userId: req.user?.id,
        resourceId: req.params[resourceParam || 'id'],
        endpoint: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Ownership verification failed',
        error: 'OWNERSHIP_CHECK_FAILED'
      });
    }
  };
};

/**
 * Combined ownership or role authorization
 */
const requireOwnershipOrRole = (roles, options = {}) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          error: 'NOT_AUTHENTICATED'
        });
      }

      const userRole = req.user.role;
      const allowedRoles = Array.isArray(roles) ? roles : [roles];

      // Check if user has required role
      if (allowedRoles.includes(userRole)) {
        logger.debug('Role authorization successful (bypass ownership)', {
          userId: req.user.id,
          role: userRole,
          endpoint: req.path
        });
        return next();
      }

      // If no role match, check ownership
      const { resourceParam = 'id', resourceType = 'user' } = options;
      const resourceId = req.params[resourceParam];
      const userId = req.user.id;

      if (resourceType === 'user' && resourceId === userId) {
        logger.debug('Ownership authorization successful', {
          userId,
          resourceId,
          endpoint: req.path
        });
        return next();
      }

      // For other resources, check ownership in database
      if (resourceType !== 'user') {
        let resource;
        
        switch (resourceType) {
          case 'task':
            resource = await Task.findById(resourceId).select('createdBy').lean();
            break;
          default:
            return res.status(400).json({
              success: false,
              message: 'Invalid resource type',
              error: 'INVALID_RESOURCE_TYPE'
            });
        }

        if (resource && resource.createdBy.toString() === userId) {
          logger.debug('Resource ownership successful', {
            userId,
            resourceId,
            resourceType,
            endpoint: req.path
          });
          return next();
        }
      }

      // Neither role nor ownership satisfied
      logger.security('Authorization failed - neither role nor ownership satisfied', {
        userId,
        userRole,
        requiredRoles: allowedRoles,
        resourceId,
        resourceType,
        endpoint: req.path,
        ip: req.ip
      });

      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions - requires role or ownership',
        error: 'AUTHORIZATION_FAILED',
        required: {
          roles: allowedRoles,
          ownership: true
        },
        current: {
          role: userRole,
          isOwner: false
        }
      });

    } catch (error) {
      logger.error('Authorization check failed', error, {
        userId: req.user?.id,
        endpoint: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Authorization check failed',
        error: 'AUTHORIZATION_CHECK_FAILED'
      });
    }
  };
};

/**
 * Task-specific access control
 */
const requireTaskAccess = (accessTypes = ['owner', 'assignee', 'collaborator', 'admin']) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          error: 'NOT_AUTHENTICATED'
        });
      }

      const taskId = req.params.id;
      const userId = req.user.id;
      const userRole = req.user.role;

      // Admin always has access
      if (accessTypes.includes('admin') && ['admin', 'manager'].includes(userRole)) {
        logger.debug('Task access granted - admin role', {
          userId,
          taskId,
          role: userRole,
          endpoint: req.path
        });
        return next();
      }

      // Get task with user relationships
      const task = await Task.findById(taskId)
        .select('createdBy assignedTo collaborators')
        .lean();

      if (!task) {
        return res.status(404).json({
          success: false,
          message: 'Task not found',
          error: 'TASK_NOT_FOUND'
        });
      }

      let hasAccess = false;
      let accessReason = '';

      // Check owner access
      if (accessTypes.includes('owner') && task.createdBy.toString() === userId) {
        hasAccess = true;
        accessReason = 'owner';
      }

      // Check assignee access
      if (!hasAccess && accessTypes.includes('assignee') && 
          task.assignedTo && task.assignedTo.some(id => id.toString() === userId)) {
        hasAccess = true;
        accessReason = 'assignee';
      }

      // Check collaborator access
      if (!hasAccess && accessTypes.includes('collaborator') && 
          task.collaborators && task.collaborators.some(id => id.toString() === userId)) {
        hasAccess = true;
        accessReason = 'collaborator';
      }

      if (!hasAccess) {
        logger.security('Task access denied', {
          userId,
          taskId,
          userRole,
          requiredAccess: accessTypes,
          isOwner: task.createdBy.toString() === userId,
          isAssignee: task.assignedTo?.some(id => id.toString() === userId),
          isCollaborator: task.collaborators?.some(id => id.toString() === userId),
          endpoint: req.path,
          ip: req.ip
        });

        return res.status(403).json({
          success: false,
          message: 'You do not have access to this task',
          error: 'TASK_ACCESS_DENIED',
          required: accessTypes
        });
      }

      // Attach task access info to request
      req.taskAccess = {
        taskId,
        accessReason,
        isOwner: task.createdBy.toString() === userId,
        isAssignee: task.assignedTo?.some(id => id.toString() === userId),
        isCollaborator: task.collaborators?.some(id => id.toString() === userId)
      };

      logger.debug('Task access granted', {
        userId,
        taskId,
        accessReason,
        endpoint: req.path
      });

      next();

    } catch (error) {
      logger.error('Task access check failed', error, {
        userId: req.user?.id,
        taskId: req.params?.id,
        endpoint: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Task access check failed',
        error: 'TASK_ACCESS_CHECK_FAILED'
      });
    }
  };
};

/**
 * Comment ownership verification
 */
const requireCommentOwnership = () => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          error: 'NOT_AUTHENTICATED'
        });
      }

      const { id: taskId, commentId } = req.params;
      const userId = req.user.id;
      const userRole = req.user.role;

      // Admin can modify any comment
      if (['admin', 'manager'].includes(userRole)) {
        return next();
      }

      // Get task and find the comment
      const task = await Task.findById(taskId).select('comments').lean();

      if (!task) {
        return res.status(404).json({
          success: false,
          message: 'Task not found',
          error: 'TASK_NOT_FOUND'
        });
      }

      const comment = task.comments.find(c => c._id.toString() === commentId);

      if (!comment) {
        return res.status(404).json({
          success: false,
          message: 'Comment not found',
          error: 'COMMENT_NOT_FOUND'
        });
      }

      if (comment.author.toString() !== userId) {
        logger.security('Comment ownership violation', {
          userId,
          commentId,
          commentAuthor: comment.author,
          endpoint: req.path,
          ip: req.ip
        });

        return res.status(403).json({
          success: false,
          message: 'You can only modify your own comments',
          error: 'COMMENT_OWNERSHIP_VIOLATION'
        });
      }

      next();

    } catch (error) {
      logger.error('Comment ownership check failed', error, {
        userId: req.user?.id,
        commentId: req.params?.commentId,
        endpoint: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Comment ownership check failed',
        error: 'COMMENT_OWNERSHIP_CHECK_FAILED'
      });
    }
  };
};

/**
 * Attachment ownership verification
 */
const requireAttachmentOwnership = () => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          error: 'NOT_AUTHENTICATED'
        });
      }

      const { id: taskId, attachmentId } = req.params;
      const userId = req.user.id;
      const userRole = req.user.role;

      // Admin can modify any attachment
      if (['admin', 'manager'].includes(userRole)) {
        return next();
      }

      // Get task and find the attachment
      const task = await Task.findById(taskId).select('attachments').lean();

      if (!task) {
        return res.status(404).json({
          success: false,
          message: 'Task not found',
          error: 'TASK_NOT_FOUND'
        });
      }

      const attachment = task.attachments.find(a => a._id.toString() === attachmentId);

      if (!attachment) {
        return res.status(404).json({
          success: false,
          message: 'Attachment not found',
          error: 'ATTACHMENT_NOT_FOUND'
        });
      }

      if (attachment.uploadedBy.toString() !== userId) {
        logger.security('Attachment ownership violation', {
          userId,
          attachmentId,
          uploadedBy: attachment.uploadedBy,
          endpoint: req.path,
          ip: req.ip
        });

        return res.status(403).json({
          success: false,
          message: 'You can only modify attachments you uploaded',
          error: 'ATTACHMENT_OWNERSHIP_VIOLATION'
        });
      }

      next();

    } catch (error) {
      logger.error('Attachment ownership check failed', error, {
        userId: req.user?.id,
        attachmentId: req.params?.attachmentId,
        endpoint: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Attachment ownership check failed',
        error: 'ATTACHMENT_OWNERSHIP_CHECK_FAILED'
      });
    }
  };
};

/**
 * API key authentication for service-to-service communication
 */
const authenticateApiKey = () => {
  return async (req, res, next) => {
    try {
      const apiKey = req.headers['x-api-key'] || req.query.apiKey;

      if (!apiKey) {
        return res.status(401).json({
          success: false,
          message: 'API key is required',
          error: 'MISSING_API_KEY'
        });
      }

      const keyData = await authService.validateApiKey(apiKey);

      if (!keyData) {
        logger.security('Invalid API key used', {
          apiKey: apiKey.substring(0, 12) + '...',
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.path
        });

        return res.status(401).json({
          success: false,
          message: 'Invalid API key',
          error: 'INVALID_API_KEY'
        });
      }

      // Attach API key info to request
      req.apiKey = {
        userId: keyData.userId,
        name: keyData.name,
        permissions: keyData.permissions
      };

      logger.debug('API key authentication successful', {
        userId: keyData.userId,
        keyName: keyData.name,
        endpoint: req.path
      });

      next();

    } catch (error) {
      logger.error('API key authentication failed', error, {
        endpoint: req.path,
        ip: req.ip
      });

      return res.status(500).json({
        success: false,
        message: 'API key authentication failed',
        error: 'API_KEY_AUTH_FAILED'
      });
    }
  };
};

/**
 * Rate limiting for authentication endpoints
 */
const authRateLimit = () => {
  return async (req, res, next) => {
    try {
      const ip = req.ip;
      const endpoint = req.path;
      const key = `auth_rate_limit:${ip}:${endpoint}`;
      
      const attempts = await cache.incr(key, 900); // 15 minutes TTL
      
      if (attempts > 10) { // 10 attempts per 15 minutes
        logger.security('Authentication rate limit exceeded', {
          ip,
          endpoint,
          attempts,
          userAgent: req.get('User-Agent')
        });

        return res.status(429).json({
          success: false,
          message: 'Too many authentication attempts. Please try again later.',
          error: 'AUTH_RATE_LIMIT_EXCEEDED',
          retryAfter: 900 // seconds
        });
      }

      next();

    } catch (error) {
      logger.error('Auth rate limit check failed', error);
      // Continue on error - don't block legitimate requests
      next();
    }
  };
};

module.exports = {
  authenticate,
  optionalAuth,
  requireRole,
  requireOwnership,
  requireOwnershipOrRole,
  requireTaskAccess,
  requireCommentOwnership,
  requireAttachmentOwnership,
  authenticateApiKey,
  authRateLimit,
  extractToken
};