/**
 * Application Constants
 * Centralized constants and enums
 */

/**
 * User Roles
 */
const USER_ROLES = {
    USER: 'user',
    MANAGER: 'manager',
    ADMIN: 'admin'
  };
  
  /**
   * Task Status
   */
  const TASK_STATUS = {
    TODO: 'todo',
    IN_PROGRESS: 'in-progress',
    REVIEW: 'review',
    TESTING: 'testing',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled'
  };
  
  /**
   * Task Priority
   */
  const TASK_PRIORITY = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    URGENT: 'urgent'
  };
  
  /**
   * Notification Types
   */
  const NOTIFICATION_TYPES = {
    TASK_ASSIGNED: 'task_assigned',
    TASK_UPDATED: 'task_updated',
    TASK_COMPLETED: 'task_completed',
    TASK_DELETED: 'task_deleted',
    COMMENT_ADDED: 'comment_added',
    MENTION: 'mention',
    SYSTEM: 'system'
  };
  
  /**
   * File Types
   */
  const FILE_TYPES = {
    IMAGE: {
      JPEG: 'image/jpeg',
      PNG: 'image/png',
      GIF: 'image/gif',
      WEBP: 'image/webp'
    },
    DOCUMENT: {
      PDF: 'application/pdf',
      DOC: 'application/msword',
      DOCX: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      TXT: 'text/plain'
    },
    SPREADSHEET: {
      XLS: 'application/vnd.ms-excel',
      XLSX: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      CSV: 'text/csv'
    }
  };
  
  /**
   * HTTP Status Codes
   */
  const HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    RATE_LIMITED: 429,
    INTERNAL_ERROR: 500
  };
  
  /**
   * Error Codes
   */
  const ERROR_CODES = {
    VALIDATION_FAILED: 'VALIDATION_FAILED',
    USER_NOT_FOUND: 'USER_NOT_FOUND',
    TASK_NOT_FOUND: 'TASK_NOT_FOUND',
    UNAUTHORIZED: 'UNAUTHORIZED',
    FORBIDDEN: 'FORBIDDEN',
    TOKEN_EXPIRED: 'TOKEN_EXPIRED',
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    EMAIL_ALREADY_EXISTS: 'EMAIL_ALREADY_EXISTS',
    USERNAME_TAKEN: 'USERNAME_TAKEN',
    FILE_TOO_LARGE: 'FILE_TOO_LARGE',
    INVALID_FILE_TYPE: 'INVALID_FILE_TYPE',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED'
  };
  
  /**
   * Cache Keys
   */
  const CACHE_KEYS = {
    USER_PROFILE: 'user_profile',
    USER_SESSIONS: 'user_sessions',
    TASK_STATS: 'task_stats',
    OVERDUE_TASKS: 'overdue_tasks',
    NOTIFICATION_COUNT: 'notification_count'
  };
  
  /**
   * Cache TTL (in seconds)
   */
  const CACHE_TTL = {
    SHORT: 300,      // 5 minutes
    MEDIUM: 1800,    // 30 minutes
    LONG: 3600,      // 1 hour
    DAY: 86400,      // 24 hours
    WEEK: 604800     // 7 days
  };
  
  /**
   * Pagination Defaults
   */
  const PAGINATION = {
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 10,
    MAX_LIMIT: 100,
    DEFAULT_SORT: '-createdAt'
  };
  
  /**
   * File Upload Limits
   */
  const FILE_LIMITS = {
    AVATAR_SIZE: 2 * 1024 * 1024,      // 2MB
    ATTACHMENT_SIZE: 10 * 1024 * 1024,  // 10MB
    MAX_FILES_PER_TASK: 10,
    ALLOWED_AVATAR_TYPES: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    ALLOWED_ATTACHMENT_TYPES: [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'application/pdf', 'text/plain',
      'application/msword', 
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/csv'
    ]
  };
  
  /**
   * Rate Limiting
   */
  const RATE_LIMITS = {
    GENERAL: {
      WINDOW_MS: 15 * 60 * 1000,  // 15 minutes
      MAX_REQUESTS: 100
    },
    AUTH: {
      WINDOW_MS: 15 * 60 * 1000,  // 15 minutes
      MAX_REQUESTS: 5
    },
    UPLOAD: {
      WINDOW_MS: 60 * 60 * 1000,  // 1 hour
      MAX_REQUESTS: 20
    }
  };
  
  /**
   * Validation Rules
   */
  const VALIDATION = {
    PASSWORD_MIN_LENGTH: 8,
    USERNAME_MIN_LENGTH: 3,
    USERNAME_MAX_LENGTH: 30,
    NAME_MAX_LENGTH: 50,
    EMAIL_MAX_LENGTH: 255,
    TASK_TITLE_MAX_LENGTH: 200,
    TASK_DESCRIPTION_MAX_LENGTH: 5000,
    COMMENT_MAX_LENGTH: 2000,
    BIO_MAX_LENGTH: 500,
    MAX_TAGS_PER_TASK: 10,
    MAX_ASSIGNEES_PER_TASK: 10
  };
  
  /**
   * Time Formats
   */
  const TIME_FORMATS = {
    ISO: 'YYYY-MM-DDTHH:mm:ss.SSSZ',
    DATE_ONLY: 'YYYY-MM-DD',
    TIME_ONLY: 'HH:mm:ss',
    HUMAN_READABLE: 'MMM DD, YYYY HH:mm'
  };
  
  /**
   * Environment Types
   */
  const ENVIRONMENTS = {
    DEVELOPMENT: 'development',
    TESTING: 'test',
    STAGING: 'staging',
    PRODUCTION: 'production'
  };
  
  /**
   * Email Templates
   */
  const EMAIL_TEMPLATES = {
    WELCOME: 'welcome',
    EMAIL_VERIFICATION: 'email-verification',
    PASSWORD_RESET: 'password-reset',
    TASK_ASSIGNED: 'task-assigned',
    TASK_COMPLETED: 'task-completed',
    DAILY_DIGEST: 'daily-digest',
    WEEKLY_DIGEST: 'weekly-digest'
  };
  
  /**
   * WebSocket Events
   */
  const SOCKET_EVENTS = {
    CONNECTION: 'connection',
    DISCONNECT: 'disconnect',
    JOIN_TASK: 'join_task',
    LEAVE_TASK: 'leave_task',
    TASK_UPDATED: 'task_updated',
    TASK_CREATED: 'task_created',
    TASK_DELETED: 'task_deleted',
    USER_TYPING: 'user_typing',
    USER_STOPPED_TYPING: 'user_stopped_typing',
    NOTIFICATION: 'notification'
  };
  
  /**
   * API Response Messages
   */
  const MESSAGES = {
    SUCCESS: {
      USER_CREATED: 'User created successfully',
      USER_UPDATED: 'User updated successfully',
      USER_DELETED: 'User deleted successfully',
      TASK_CREATED: 'Task created successfully',
      TASK_UPDATED: 'Task updated successfully',
      TASK_DELETED: 'Task deleted successfully',
      LOGIN_SUCCESS: 'Login successful',
      LOGOUT_SUCCESS: 'Logged out successfully',
      PASSWORD_CHANGED: 'Password changed successfully',
      EMAIL_SENT: 'Email sent successfully'
    },
    ERROR: {
      INVALID_CREDENTIALS: 'Invalid email or password',
      USER_NOT_FOUND: 'User not found',
      TASK_NOT_FOUND: 'Task not found',
      UNAUTHORIZED: 'Access denied',
      FORBIDDEN: 'Insufficient permissions',
      VALIDATION_FAILED: 'Validation failed',
      FILE_TOO_LARGE: 'File size exceeds maximum limit',
      INVALID_FILE_TYPE: 'File type not allowed',
      RATE_LIMIT_EXCEEDED: 'Too many requests, please try again later',
      INTERNAL_ERROR: 'Internal server error'
    }
  };
  
  /**
   * Regular Expressions
   */
  const REGEX = {
    EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    USERNAME: /^[a-zA-Z0-9_-]+$/,
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    HEX_COLOR: /^#[0-9A-F]{6}$/i,
    PHONE: /^\+?[\d\s\-\(\)]+$/,
    URL: /^https?:\/\/.+/
  };
  
  module.exports = {
    USER_ROLES,
    TASK_STATUS,
    TASK_PRIORITY,
    NOTIFICATION_TYPES,
    FILE_TYPES,
    HTTP_STATUS,
    ERROR_CODES,
    CACHE_KEYS,
    CACHE_TTL,
    PAGINATION,
    FILE_LIMITS,
    RATE_LIMITS,
    VALIDATION,
    TIME_FORMATS,
    ENVIRONMENTS,
    EMAIL_TEMPLATES,
    SOCKET_EVENTS,
    MESSAGES,
    REGEX
  };