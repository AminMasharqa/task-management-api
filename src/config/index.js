/**
 * Application Configuration
 * Centralized configuration management with environment-based settings
 */

const path = require('path');

// Ensure environment variables are loaded
require('dotenv').config();

/**
 * Get environment variable with default value and type conversion
 */
function getEnvVar(key, defaultValue, type = 'string') {
  const value = process.env[key];
  
  if (value === undefined) {
    if (defaultValue === undefined) {
      throw new Error(`Required environment variable ${key} is not set`);
    }
    return defaultValue;
  }

  switch (type) {
    case 'number':
      const num = Number(value);
      if (isNaN(num)) {
        throw new Error(`Environment variable ${key} must be a number, got: ${value}`);
      }
      return num;
    case 'boolean':
      return value.toLowerCase() === 'true';
    case 'array':
      return value.split(',').map(item => item.trim()).filter(Boolean);
    default:
      return value;
  }
}

/**
 * Validate required configuration
 */
function validateConfig() {
  const requiredVars = [
    'JWT_SECRET',
    'MONGODB_URI'
  ];

  const missing = requiredVars.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  // Validate JWT secret length
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long for security');
  }
}

// Validate configuration on startup
validateConfig();

/**
 * Configuration object
 */
const config = {
  // Application settings
  nodeEnv: getEnvVar('NODE_ENV', 'development'),
  port: getEnvVar('PORT', 3000, 'number'),
  apiVersion: getEnvVar('API_VERSION', 'v1'),
  
  // Database configuration
  database: {
    uri: getEnvVar('MONGODB_URI'),
    testUri: getEnvVar('MONGODB_TEST_URI', 'mongodb://localhost:27017/task_management_test'),
    options: {
      maxPoolSize: getEnvVar('DB_MAX_POOL_SIZE', 10, 'number'),
      minPoolSize: getEnvVar('DB_MIN_POOL_SIZE', 5, 'number'),
      maxIdleTimeMS: 30000,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    }
  },

  // Redis configuration
  redis: {
    host: getEnvVar('REDIS_HOST', 'localhost'),
    port: getEnvVar('REDIS_PORT', 6379, 'number'),
    password: getEnvVar('REDIS_PASSWORD', ''),
    db: getEnvVar('REDIS_DB', 0, 'number'),
    ttl: getEnvVar('REDIS_TTL', 3600, 'number'),
    retryDelayOnFailover: 100,
    enableReadyCheck: false,
    maxRetriesPerRequest: null,
  },

  // JWT configuration
  jwt: {
    secret: getEnvVar('JWT_SECRET'),
    refreshSecret: getEnvVar('JWT_REFRESH_SECRET', getEnvVar('JWT_SECRET')),
    expiresIn: getEnvVar('JWT_EXPIRE', '15m'),
    refreshExpiresIn: getEnvVar('JWT_REFRESH_EXPIRE', '7d'),
    issuer: 'task-management-api',
    audience: 'task-management-users'
  },

  // Security configuration
  security: {
    minPasswordLength: getEnvVar('MIN_PASSWORD_LENGTH', 8, 'number'),
    maxLoginAttempts: getEnvVar('MAX_LOGIN_ATTEMPTS', 5, 'number'),
    lockoutTime: getEnvVar('LOCKOUT_TIME', 15, 'number'), // minutes
    saltRounds: 12,
  },

  // Rate limiting
  rateLimit: {
    windowMs: getEnvVar('RATE_LIMIT_WINDOW_MS', 15 * 60 * 1000, 'number'), // 15 minutes
    maxRequests: getEnvVar('RATE_LIMIT_MAX_REQUESTS', 100, 'number'),
    message: 'Too many requests from this IP, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
  },

  // CORS configuration
  cors: {
    origin: getEnvVar('CORS_ORIGINS', 'http://localhost:3000', 'array'),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  },

  // Email configuration
  email: {
    smtp: {
      host: getEnvVar('SMTP_HOST', 'smtp.gmail.com'),
      port: getEnvVar('SMTP_PORT', 587, 'number'),
      secure: getEnvVar('SMTP_SECURE', false, 'boolean'),
      auth: {
        user: getEnvVar('SMTP_USER', ''),
        pass: getEnvVar('SMTP_PASS', '')
      }
    },
    from: {
      email: getEnvVar('FROM_EMAIL', 'noreply@taskmanager.com'),
      name: getEnvVar('FROM_NAME', 'Task Manager')
    },
    mockService: getEnvVar('MOCK_EMAIL_SERVICE', true, 'boolean')
  },

  // File upload configuration
  upload: {
    maxFileSize: getEnvVar('MAX_FILE_SIZE', 5 * 1024 * 1024, 'number'), // 5MB
    allowedTypes: getEnvVar('ALLOWED_FILE_TYPES', 'image/jpeg,image/png,image/gif,application/pdf', 'array'),
    uploadPath: path.join(process.cwd(), getEnvVar('UPLOAD_PATH', 'uploads/')),
    cleanupInterval: 24 * 60 * 60 * 1000, // 24 hours
  },

  // Socket.IO configuration
  socket: {
    corsOrigin: getEnvVar('SOCKET_CORS_ORIGIN', 'http://localhost:3000'),
    pingTimeout: getEnvVar('SOCKET_PING_TIMEOUT', 60000, 'number'),
    pingInterval: getEnvVar('SOCKET_PING_INTERVAL', 25000, 'number'),
    transports: ['websocket', 'polling'],
  },

  // Logging configuration
  logging: {
    level: getEnvVar('LOG_LEVEL', 'info'),
    file: getEnvVar('LOG_FILE', 'logs/app.log'),
    maxSize: getEnvVar('LOG_MAX_SIZE', '20m'),
    maxFiles: getEnvVar('LOG_MAX_FILES', '14d'),
    enableConsole: getEnvVar('NODE_ENV', 'development') === 'development',
    enableRequestLogging: getEnvVar('ENABLE_REQUEST_LOGGING', true, 'boolean'),
  },

  // Health check configuration
  health: {
    checkInterval: getEnvVar('HEALTH_CHECK_INTERVAL', 30000, 'number'),
    endpoints: {
      database: '/health/db',
      redis: '/health/redis',
      overall: '/health'
    }
  },

  // API Documentation
  docs: {
    enabled: getEnvVar('ENABLE_DOCS', true, 'boolean'),
    path: getEnvVar('DOCS_PATH', '/api-docs'),
    title: 'Task Management API',
    version: '1.0.0',
    description: 'Modern scalable task management API'
  },

  // External services
  external: {
    slack: {
      webhookUrl: getEnvVar('SLACK_WEBHOOK_URL', '')
    },
    github: {
      clientId: getEnvVar('GITHUB_CLIENT_ID', ''),
      clientSecret: getEnvVar('GITHUB_CLIENT_SECRET', '')
    }
  },

  // Development settings
  development: {
    debugDbQueries: getEnvVar('DEBUG_DB_QUERIES', false, 'boolean'),
    seedData: {
      adminEmail: getEnvVar('SEED_ADMIN_EMAIL', 'admin@taskmanager.com'),
      adminPassword: getEnvVar('SEED_ADMIN_PASSWORD', 'Admin123!')
    }
  }
};

/**
 * Environment-specific overrides
 */
if (config.nodeEnv === 'test') {
  config.database.uri = config.database.testUri;
  config.logging.level = 'error';
  config.logging.enableConsole = false;
}

if (config.nodeEnv === 'production') {
  config.logging.enableConsole = false;
  config.docs.enabled = false;
  config.email.mockService = false;
}

/**
 * Helper functions
 */
config.isDevelopment = () => config.nodeEnv === 'development';
config.isProduction = () => config.nodeEnv === 'production';
config.isTest = () => config.nodeEnv === 'test';

module.exports = config;