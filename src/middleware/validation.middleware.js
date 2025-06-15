/**
 * Validation Middleware
 * Input validation and sanitization using Joi schemas
 */

const Joi = require('joi');
const mongoose = require('mongoose');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Custom Joi extensions
 */
const customJoi = Joi.extend({
  type: 'objectId',
  base: Joi.string(),
  messages: {
    'objectId.invalid': '{{#label}} must be a valid ObjectId'
  },
  validate(value, helpers) {
    if (!mongoose.Types.ObjectId.isValid(value)) {
      return { value, errors: helpers.error('objectId.invalid') };
    }
    return { value };
  }
});

/**
 * Common validation schemas
 */
const commonSchemas = {
  objectId: customJoi.objectId().required(),
  optionalObjectId: customJoi.objectId(),
  email: Joi.string().email().lowercase().trim().max(255),
  password: Joi.string()
    .min(config.security.minPasswordLength)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .message('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .trim()
    .lowercase(),
  name: Joi.string()
    .min(2)
    .max(50)
    .trim()
    .pattern(/^[a-zA-Z\s'-]+$/)
    .message('Name can only contain letters, spaces, hyphens, and apostrophes'),
  url: Joi.string().uri({ scheme: ['http', 'https'] }).max(500),
  pagination: {
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
    sort: Joi.string().max(100).default('-createdAt')
  },
  search: Joi.string().min(2).max(100).trim(),
  tags: Joi.array().items(
    Joi.string().trim().lowercase().min(1).max(30)
  ).max(10),
  priority: Joi.string().valid('low', 'medium', 'high', 'urgent'),
  status: Joi.string().valid('todo', 'in-progress', 'review', 'testing', 'completed', 'cancelled')
};

/**
 * Generic validation middleware creator
 */
const createValidator = (schema, source = 'body') => {
  return (req, res, next) => {
    try {
      const dataToValidate = req[source];
      
      const { error, value } = schema.validate(dataToValidate, {
        abortEarly: false,
        stripUnknown: true,
        convert: true
      });

      if (error) {
        const validationErrors = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        }));

        logger.warn('Validation failed', {
          endpoint: req.path,
          source,
          errors: validationErrors,
          userId: req.user?.id
        });

        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: validationErrors
        });
      }

      // Replace original data with validated and sanitized data
      req[source] = value;
      
      logger.debug('Validation successful', {
        endpoint: req.path,
        source,
        fields: Object.keys(value)
      });

      next();

    } catch (validationError) {
      logger.error('Validation middleware error', validationError, {
        endpoint: req.path,
        source
      });

      return res.status(500).json({
        success: false,
        message: 'Validation processing failed',
        error: 'VALIDATION_ERROR'
      });
    }
  };
};

/**
 * Authentication validation schemas
 */
const authSchemas = {
  register: Joi.object({
    email: commonSchemas.email.required(),
    password: commonSchemas.password.required(),
    firstName: commonSchemas.name.required(),
    lastName: commonSchemas.name.required(),
    username: commonSchemas.username.required(),
    termsAccepted: Joi.boolean().valid(true).required()
      .messages({ 'any.only': 'You must accept the terms and conditions' })
  }),

  login: Joi.object({
    email: Joi.string().required().max(255).trim(),
    password: Joi.string().required().max(128),
    rememberMe: Joi.boolean().default(false)
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().required().max(128),
    newPassword: commonSchemas.password.required(),
    confirmPassword: Joi.string().required().valid(Joi.ref('newPassword'))
      .messages({ 'any.only': 'Passwords do not match' })
  }),

  forgotPassword: Joi.object({
    email: commonSchemas.email.required()
  }),

  resetPassword: Joi.object({
    token: Joi.string().required().length(64),
    password: commonSchemas.password.required(),
    confirmPassword: Joi.string().required().valid(Joi.ref('password'))
      .messages({ 'any.only': 'Passwords do not match' })
  }),

  emailVerification: Joi.object({
    token: Joi.string().required().length(64)
  }),

  updateProfile: Joi.object({
    firstName: commonSchemas.name,
    lastName: commonSchemas.name,
    username: commonSchemas.username,
    profile: Joi.object({
      bio: Joi.string().max(500).trim().allow(''),
      website: commonSchemas.url,
      location: Joi.string().max(100).trim(),
      title: Joi.string().max(100).trim(),
      company: Joi.string().max(100).trim(),
      skills: Joi.array().items(Joi.string().trim().max(50)).max(20),
      socialLinks: Joi.object({
        github: Joi.string().max(100).trim(),
        linkedin: Joi.string().max(100).trim(),
        twitter: Joi.string().max(100).trim(),
        slack: Joi.string().max(100).trim()
      })
    })
  }),

  twoFactorCode: Joi.object({
    code: Joi.string().length(6).pattern(/^\d+$/).required()
      .messages({ 'string.pattern.base': 'Code must be 6 digits' })
  }),

  disableTwoFactor: Joi.object({
    password: Joi.string().required().max(128),
    code: Joi.string().length(6).pattern(/^\d+$/).required()
  })
};

/**
 * User validation schemas
 */
const userSchemas = {
  userQuery: Joi.object({
    ...commonSchemas.pagination,
    role: Joi.string().valid('user', 'manager', 'admin'),
    isActive: Joi.boolean(),
    emailVerified: Joi.boolean(),
    search: commonSchemas.search
  }),

  userSearch: Joi.object({
    q: commonSchemas.search.required(),
    limit: Joi.number().integer().min(1).max(50).default(10)
  }),

  updateUser: Joi.object({
    firstName: commonSchemas.name,
    lastName: commonSchemas.name,
    username: commonSchemas.username,
    email: commonSchemas.email,
    profile: Joi.object({
      bio: Joi.string().max(500).trim().allow(''),
      website: commonSchemas.url,
      location: Joi.string().max(100).trim(),
      title: Joi.string().max(100).trim(),
      company: Joi.string().max(100).trim(),
      skills: Joi.array().items(Joi.string().trim().max(50)).max(20)
    })
  }).min(1),

  userStatus: Joi.object({
    isActive: Joi.boolean().required()
  }),

  userRole: Joi.object({
    role: Joi.string().valid('user', 'manager', 'admin').required()
  }),

  userPreferences: Joi.object({
    notifications: Joi.object({
      email: Joi.boolean(),
      push: Joi.boolean(),
      taskUpdates: Joi.boolean(),
      comments: Joi.boolean(),
      assignments: Joi.boolean(),
      mentions: Joi.boolean(),
      dailyDigest: Joi.boolean(),
      weeklyDigest: Joi.boolean()
    }),
    privacy: Joi.object({
      profileVisible: Joi.boolean(),
      activityVisible: Joi.boolean(),
      emailVisible: Joi.boolean()
    }),
    ui: Joi.object({
      theme: Joi.string().valid('light', 'dark', 'auto'),
      language: Joi.string().valid('en', 'es', 'fr', 'de', 'pt'),
      timezone: Joi.string().max(50),
      dateFormat: Joi.string().valid('MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD')
    })
  }),

  followQuery: Joi.object({
    ...commonSchemas.pagination
  }),

  notificationQuery: Joi.object({
    ...commonSchemas.pagination,
    unreadOnly: Joi.boolean().default(false)
  }),

  activityQuery: Joi.object({
    ...commonSchemas.pagination,
    action: Joi.string().valid('login', 'logout', 'task_created', 'task_completed', 'profile_updated'),
    dateFrom: Joi.date().iso(),
    dateTo: Joi.date().iso().min(Joi.ref('dateFrom'))
  }),

  deactivateAccount: Joi.object({
    password: Joi.string().required().max(128),
    reason: Joi.string().max(500).trim(),
    feedback: Joi.string().max(1000).trim()
  }),

  bulkInvite: Joi.object({
    emails: Joi.array().items(commonSchemas.email).min(1).max(50).required(),
    role: Joi.string().valid('user', 'manager').default('user'),
    message: Joi.string().max(500).trim()
  }),

  bulkUpdate: Joi.object({
    userIds: Joi.array().items(commonSchemas.objectId).min(1).max(100).required(),
    updates: Joi.object({
      role: Joi.string().valid('user', 'manager', 'admin'),
      isActive: Joi.boolean()
    }).min(1).required()
  }),

  bulkDelete: Joi.object({
    userIds: Joi.array().items(commonSchemas.objectId).min(1).max(100).required(),
    reason: Joi.string().max(500).trim()
  })
};

/**
 * Task validation schemas
 */
const taskSchemas = {
  taskQuery: Joi.object({
    ...commonSchemas.pagination,
    status: commonSchemas.status,
    priority: commonSchemas.priority,
    assignedTo: commonSchemas.optionalObjectId,
    createdBy: commonSchemas.optionalObjectId,
    tags: Joi.string().max(200),
    dueBefore: Joi.date().iso(),
    dueAfter: Joi.date().iso(),
    search: commonSchemas.search
  }),

  createTask: Joi.object({
    title: Joi.string().min(3).max(200).trim().required(),
    description: Joi.string().max(5000).trim().allow(''),
    status: commonSchemas.status.default('todo'),
    priority: commonSchemas.priority.default('medium'),
    assignedTo: Joi.array().items(commonSchemas.objectId).max(10),
    collaborators: Joi.array().items(commonSchemas.objectId).max(20),
    tags: commonSchemas.tags,
    dueDate: Joi.date().iso().greater('now'),
    startDate: Joi.date().iso(),
    estimatedHours: Joi.number().min(0).max(1000),
    labels: Joi.array().items(
      Joi.object({
        name: Joi.string().trim().min(1).max(50).required(),
        color: Joi.string().pattern(/^#[0-9A-F]{6}$/i).message('Color must be a valid hex color')
      })
    ).max(10),
    checklist: Joi.array().items(
      Joi.object({
        text: Joi.string().trim().min(1).max(200).required(),
        completed: Joi.boolean().default(false),
        position: Joi.number().integer().min(0).default(0)
      })
    ).max(50),
    customFields: Joi.array().items(
      Joi.object({
        name: Joi.string().trim().min(1).max(50).required(),
        type: Joi.string().valid('text', 'number', 'date', 'select', 'multiselect', 'boolean', 'url').required(),
        value: Joi.any(),
        options: Joi.array().items(Joi.string().trim().max(100)).max(50),
        required: Joi.boolean().default(false)
      })
    ).max(20)
  }),

  updateTask: Joi.object({
    title: Joi.string().min(3).max(200).trim(),
    description: Joi.string().max(5000).trim().allow(''),
    status: commonSchemas.status,
    priority: commonSchemas.priority,
    assignedTo: Joi.array().items(commonSchemas.objectId).max(10),
    collaborators: Joi.array().items(commonSchemas.objectId).max(20),
    tags: commonSchemas.tags,
    dueDate: Joi.date().iso().allow(null),
    startDate: Joi.date().iso().allow(null),
    estimatedHours: Joi.number().min(0).max(1000).allow(null),
    progress: Joi.number().min(0).max(100),
    labels: Joi.array().items(
      Joi.object({
        name: Joi.string().trim().min(1).max(50).required(),
        color: Joi.string().pattern(/^#[0-9A-F]{6}$/i)
      })
    ).max(10),
    checklist: Joi.array().items(
      Joi.object({
        text: Joi.string().trim().min(1).max(200).required(),
        completed: Joi.boolean().default(false),
        position: Joi.number().integer().min(0).default(0)
      })
    ).max(50)
  }).min(1),

  taskStatus: Joi.object({
    status: commonSchemas.status.required()
  }),

  taskPriority: Joi.object({
    priority: commonSchemas.priority.required()
  }),

  taskAssignment: Joi.object({
    userIds: Joi.array().items(commonSchemas.objectId).min(1).max(10).required()
  }),

  taskTags: Joi.object({
    tags: commonSchemas.tags.required()
  }),

  taskDueDate: Joi.object({
    dueDate: Joi.date().iso().greater('now').allow(null).required()
  }),

  duplicateTask: Joi.object({
    title: Joi.string().min(3).max(200).trim(),
    assignToCreator: Joi.boolean().default(false),
    clearDueDate: Joi.boolean().default(false),
    clearAssignees: Joi.boolean().default(false),
    includeChecklist: Joi.boolean().default(true),
    includeAttachments: Joi.boolean().default(false)
  }),

  taskSearch: Joi.object({
    q: commonSchemas.search.required(),
    limit: Joi.number().integer().min(1).max(50).default(20)
  }),

  statsQuery: Joi.object({
    timeframe: Joi.string().pattern(/^\d+d$/).default('30d'),
    groupBy: Joi.string().valid('day', 'week', 'month').default('day')
  }),

  commentQuery: Joi.object({
    ...commonSchemas.pagination
  }),

  createComment: Joi.object({
    content: Joi.string().min(1).max(2000).trim().required(),
    mentions: Joi.array().items(commonSchemas.objectId).max(20),
    parentComment: commonSchemas.optionalObjectId
  }),

  updateComment: Joi.object({
    content: Joi.string().min(1).max(2000).trim().required()
  }),

  bulkStatusUpdate: Joi.object({
    taskIds: Joi.array().items(commonSchemas.objectId).min(1).max(100).required(),
    status: commonSchemas.status.required()
  }),

  bulkAssign: Joi.object({
    taskIds: Joi.array().items(commonSchemas.objectId).min(1).max(100).required(),
    userIds: Joi.array().items(commonSchemas.objectId).min(1).max(10).required(),
    action: Joi.string().valid('assign', 'unassign').default('assign')
  }),

  bulkDelete: Joi.object({
    taskIds: Joi.array().items(commonSchemas.objectId).min(1).max(100).required(),
    reason: Joi.string().max(500).trim()
  }),

  analyticsQuery: Joi.object({
    dateFrom: Joi.date().iso(),
    dateTo: Joi.date().iso().min(Joi.ref('dateFrom')),
    groupBy: Joi.string().valid('day', 'week', 'month').default('week'),
    userId: commonSchemas.optionalObjectId
  })
};

/**
 * Template validation schemas
 */
const templateSchemas = {
  templateQuery: Joi.object({
    ...commonSchemas.pagination,
    category: Joi.string().max(50).trim(),
    tags: Joi.string().max(200)
  }),

  createTemplate: Joi.object({
    name: Joi.string().min(3).max(100).trim().required(),
    description: Joi.string().max(500).trim().allow(''),
    category: Joi.string().max(50).trim().required(),
    tags: commonSchemas.tags,
    template: Joi.object({
      title: Joi.string().min(3).max(200).trim().required(),
      description: Joi.string().max(5000).trim().allow(''),
      priority: commonSchemas.priority.default('medium'),
      estimatedHours: Joi.number().min(0).max(1000),
      labels: Joi.array().items(
        Joi.object({
          name: Joi.string().trim().min(1).max(50).required(),
          color: Joi.string().pattern(/^#[0-9A-F]{6}$/i)
        })
      ).max(10),
      checklist: Joi.array().items(
        Joi.object({
          text: Joi.string().trim().min(1).max(200).required(),
          position: Joi.number().integer().min(0).default(0)
        })
      ).max(50)
    }).required()
  }),

  createFromTemplate: Joi.object({
    title: Joi.string().min(3).max(200).trim(),
    assignedTo: Joi.array().items(commonSchemas.objectId).max(10),
    dueDate: Joi.date().iso().greater('now'),
    customizations: Joi.object({
      priority: commonSchemas.priority,
      tags: commonSchemas.tags,
      additionalChecklist: Joi.array().items(
        Joi.object({
          text: Joi.string().trim().min(1).max(200).required(),
          position: Joi.number().integer().min(0).default(0)
        })
      ).max(20)
    })
  })
};

/**
 * Parameter validation schemas
 */
const paramSchemas = {
  id: Joi.object({
    id: commonSchemas.objectId
  }),

  userId: Joi.object({
    id: commonSchemas.objectId,
    userId: commonSchemas.objectId
  }),

  taskId: Joi.object({
    id: commonSchemas.objectId
  }),

  commentId: Joi.object({
    id: commonSchemas.objectId,
    commentId: commonSchemas.objectId
  }),

  attachmentId: Joi.object({
    id: commonSchemas.objectId,
    attachmentId: commonSchemas.objectId
  }),

  sessionId: Joi.object({
    sessionId: Joi.string().uuid().required()
  }),

  templateId: Joi.object({
    templateId: commonSchemas.objectId
  }),

  notificationId: Joi.object({
    id: commonSchemas.objectId,
    notificationId: Joi.string().uuid().required()
  }),

  teamId: Joi.object({
    teamId: commonSchemas.objectId
  })
};

/**
 * Development validation schemas
 */
const devSchemas = {
  createTestUser: Joi.object({
    email: commonSchemas.email,
    password: Joi.string().min(6).max(128),
    role: Joi.string().valid('user', 'manager', 'admin').default('user'),
    emailVerified: Joi.boolean().default(true)
  }),

  generateTokens: Joi.object({
    userId: commonSchemas.objectId.required(),
    expiresIn: Joi.string().default('1h')
  })
};

/**
 * Request validation wrapper
 */
const validateRequest = () => {
  return (req, res, next) => {
    // This can be used as a general request validator
    // Currently just passes through, but can be extended
    next();
  };
};

/**
 * Validation middleware factory functions
 */
const validationMiddleware = {
  // Generic validators
  validateRequest,
  
  // Authentication validators
  validateRegister: () => createValidator(authSchemas.register),
  validateLogin: () => createValidator(authSchemas.login),
  validateRefreshToken: () => createValidator(authSchemas.refreshToken),
  validateChangePassword: () => createValidator(authSchemas.changePassword),
  validateForgotPassword: () => createValidator(authSchemas.forgotPassword),
  validateResetPassword: () => createValidator(authSchemas.resetPassword),
  validateEmailVerification: () => createValidator(authSchemas.emailVerification),
  validateUpdateProfile: () => createValidator(authSchemas.updateProfile),
  validateTwoFactorCode: () => createValidator(authSchemas.twoFactorCode),
  validateDisableTwoFactor: () => createValidator(authSchemas.disableTwoFactor),

  // User validators
  validateUserQuery: () => createValidator(userSchemas.userQuery, 'query'),
  validateUserSearch: () => createValidator(userSchemas.userSearch, 'query'),
  validateUpdateUser: () => createValidator(userSchemas.updateUser),
  validateUserStatus: () => createValidator(userSchemas.userStatus),
  validateUserRole: () => createValidator(userSchemas.userRole),
  validateUserPreferences: () => createValidator(userSchemas.userPreferences),
  validateFollowQuery: () => createValidator(userSchemas.followQuery, 'query'),
  validateNotificationQuery: () => createValidator(userSchemas.notificationQuery, 'query'),
  validateActivityQuery: () => createValidator(userSchemas.activityQuery, 'query'),
  validateDeactivateAccount: () => createValidator(userSchemas.deactivateAccount),
  validateBulkInvite: () => createValidator(userSchemas.bulkInvite),
  validateBulkUpdate: () => createValidator(userSchemas.bulkUpdate),
  validateBulkDelete: () => createValidator(userSchemas.bulkDelete),

  // Task validators
  validateTaskQuery: () => createValidator(taskSchemas.taskQuery, 'query'),
  validateCreateTask: () => createValidator(taskSchemas.createTask),
  validateUpdateTask: () => createValidator(taskSchemas.updateTask),
  validateTaskStatus: () => createValidator(taskSchemas.taskStatus),
  validateTaskPriority: () => createValidator(taskSchemas.taskPriority),
  validateTaskAssignment: () => createValidator(taskSchemas.taskAssignment),
  validateTaskTags: () => createValidator(taskSchemas.taskTags),
  validateTaskDueDate: () => createValidator(taskSchemas.taskDueDate),
  validateDuplicateTask: () => createValidator(taskSchemas.duplicateTask),
  validateTaskSearch: () => createValidator(taskSchemas.taskSearch, 'query'),
  validateStatsQuery: () => createValidator(taskSchemas.statsQuery, 'query'),
  validateCommentQuery: () => createValidator(taskSchemas.commentQuery, 'query'),
  validateCreateComment: () => createValidator(taskSchemas.createComment),
  validateUpdateComment: () => createValidator(taskSchemas.updateComment),
  validateBulkStatusUpdate: () => createValidator(taskSchemas.bulkStatusUpdate),
  validateBulkAssign: () => createValidator(taskSchemas.bulkAssign),
  validateAnalyticsQuery: () => createValidator(taskSchemas.analyticsQuery, 'query'),

  // Template validators
  validateTemplateQuery: () => createValidator(templateSchemas.templateQuery, 'query'),
  validateCreateTemplate: () => createValidator(templateSchemas.createTemplate),
  validateCreateFromTemplate: () => createValidator(templateSchemas.createFromTemplate),

  // Parameter validators
  validateUserId: (param = 'id') => createValidator(paramSchemas.id, 'params'),
  validateTaskId: () => createValidator(paramSchemas.taskId, 'params'),
  validateCommentId: () => createValidator(paramSchemas.commentId, 'params'),
  validateAttachmentId: () => createValidator(paramSchemas.attachmentId, 'params'),
  validateSessionId: () => createValidator(paramSchemas.sessionId, 'params'),
  validateTemplateId: () => createValidator(paramSchemas.templateId, 'params'),
  validateNotificationId: () => createValidator(paramSchemas.notificationId, 'params'),
  validateTeamId: () => createValidator(paramSchemas.teamId, 'params'),

  // Development validators
  validateCreateTestUser: () => createValidator(devSchemas.createTestUser),
  validateGenerateTokens: () => createValidator(devSchemas.generateTokens)
};

module.exports = validationMiddleware;