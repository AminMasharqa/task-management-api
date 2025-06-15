/**
 * Logger Utility
 * Structured logging with Winston for development and production
 */

const winston = require("winston");
const path = require("path");
const fs = require("fs");
const config = require("../config");

/**
 * Ensure logs directory exists
 */
const logsDir = path.dirname(config.logging.file);
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Custom log levels with colors
 */
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const logColors = {
  error: "red",
  warn: "yellow",
  info: "green",
  http: "magenta",
  debug: "cyan",
};

winston.addColors(logColors);

/**
 * Custom log formats
 */
const formats = {
  // Console format for development
  console: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    winston.format.colorize({ all: true }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      let log = `${timestamp} [${level}]: ${message}`;

      // Add metadata if present
      if (Object.keys(meta).length > 0) {
        log += `\n${JSON.stringify(meta, null, 2)}`;
      }

      return log;
    })
  ),

  // File format for production
  file: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.prettyPrint()
  ),

  // Error format with stack traces
  error: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
};

/**
 * Create transports array
 */
function createTransports() {
  const transports = [];

  // Console transport for development
  if (config.logging.enableConsole) {
    transports.push(
      new winston.transports.Console({
        level: config.logging.level,
        format: formats.console,
        handleExceptions: true,
        handleRejections: true,
      })
    );
  }

  // File transports for all environments
  if (config.logging.file) {
    // General log file
    transports.push(
      new winston.transports.File({
        filename: config.logging.file,
        level: config.logging.level,
        format: formats.file,
        maxsize: parseSize(config.logging.maxSize),
        maxFiles: config.logging.maxFiles,
        tailable: true,
        zippedArchive: true,
      })
    );

    // Error-only log file
    const errorLogFile = config.logging.file.replace(".log", ".error.log");
    transports.push(
      new winston.transports.File({
        filename: errorLogFile,
        level: "error",
        format: formats.error,
        maxsize: parseSize(config.logging.maxSize),
        maxFiles: config.logging.maxFiles,
        tailable: true,
        zippedArchive: true,
      })
    );
  }

  return transports;
}

/**
 * Parse size string to bytes
 */
function parseSize(size) {
  if (typeof size === "number") return size;

  const units = { k: 1024, m: 1024 * 1024, g: 1024 * 1024 * 1024 };
  const match = size.toLowerCase().match(/^(\d+)([kmg]?)$/);

  if (!match) return 5 * 1024 * 1024; // Default 5MB

  const [, num, unit] = match;
  return parseInt(num) * (units[unit] || 1);
}

/**
 * Create Winston logger instance
 */
const logger = winston.createLogger({
  levels: logLevels,
  level: config.logging.level,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true })
  ),
  transports: createTransports(),
  exitOnError: false,
  silent: config.isTest() && !process.env.ENABLE_LOGGING,
});

/**
 * Enhanced logging methods with context
 */
class EnhancedLogger {
  constructor(winstonLogger) {
    this.winston = winstonLogger;
  }

  /**
   * Create child logger with context
   */
  child(context) {
    return new EnhancedLogger(this.winston.child(context));
  }

  /**
   * Log with automatic context detection
   */
  log(level, message, meta = {}) {
    // Auto-detect request context
    const context = this.getContext();

    this.winston.log(level, message, {
      ...context,
      ...meta,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Error logging with stack trace
   */
  error(message, error = null, meta = {}) {
    const errorMeta = {
      ...meta,
    };

    if (error instanceof Error) {
      errorMeta.error = {
        message: error.message,
        stack: error.stack,
        name: error.name,
      };
    } else if (error) {
      errorMeta.error = error;
    }

    this.log("error", message, errorMeta);
  }

  /**
   * Warning logging
   */
  warn(message, meta = {}) {
    this.log("warn", message, meta);
  }

  /**
   * Info logging
   */
  info(message, meta = {}) {
    this.log("info", message, meta);
  }

  /**
   * HTTP request logging
   */
  http(message, meta = {}) {
    this.log("http", message, meta);
  }

  /**
   * Debug logging
   */
  debug(message, meta = {}) {
    this.log("debug", message, meta);
  }

  /**
   * Performance logging
   */
  perf(operation, duration, meta = {}) {
    this.info(`Performance: ${operation}`, {
      ...meta,
      duration: `${duration}ms`,
      performance: true,
    });
  }

  /**
   * Security logging
   */
  security(event, details = {}) {
    this.warn(`Security Event: ${event}`, {
      ...details,
      security: true,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Business logic logging
   */
  business(event, data = {}) {
    this.info(`Business Event: ${event}`, {
      ...data,
      business: true,
    });
  }

  /**
   * Database operation logging
   */
  database(operation, collection, meta = {}) {
    this.debug(`Database: ${operation} on ${collection}`, {
      ...meta,
      database: true,
    });
  }

  /**
   * API logging
   */
  api(method, path, statusCode, duration, meta = {}) {
    const level = statusCode >= 400 ? "warn" : "http";

    this.log(level, `API: ${method} ${path}`, {
      ...meta,
      api: true,
      method,
      path,
      statusCode,
      duration: `${duration}ms`,
    });
  }

  /**
   * Get execution context
   */
  getContext() {
    const context = {};

    // Add process information
    context.pid = process.pid;
    context.memory = process.memoryUsage();

    // Add request ID if available (set by middleware)
    if (global.requestId) {
      context.requestId = global.requestId;
    }

    // Add user ID if available (set by auth middleware)
    if (global.userId) {
      context.userId = global.userId;
    }

    return context;
  }

  /**
   * Create timer for performance logging
   */
  timer(operation) {
    const start = Date.now();

    return {
      end: (meta = {}) => {
        const duration = Date.now() - start;
        this.perf(operation, duration, meta);
        return duration;
      },
    };
  }

  /**
   * Log application startup
   */
  startup(service, version, port) {
    this.info("🚀 Application Starting", {
      service,
      version,
      port,
      environment: config.nodeEnv,
      nodeVersion: process.version,
      startup: true,
    });
  }

  /**
   * Log application shutdown
   */
  shutdown(reason = "unknown") {
    this.info("🛑 Application Shutting Down", {
      reason,
      uptime: process.uptime(),
      shutdown: true,
    });
  }

  /**
   * Create structured log for specific modules
   */
  module(moduleName) {
    return this.child({ module: moduleName });
  }
}

/**
 * Create enhanced logger instance
 */
const enhancedLogger = new EnhancedLogger(logger);

/**
 * Request logging middleware creator
 */
function createRequestLogger() {
  return (req, res, next) => {
    const start = Date.now();

    // Generate request ID
    req.id = require("uuid").v4();
    global.requestId = req.id;

    // Log request start
    enhancedLogger.http("Request Started", {
      method: req.method,
      url: req.url,
      userAgent: req.get("User-Agent"),
      ip: req.ip || req.connection.remoteAddress,
      requestId: req.id,
    });

    // Override res.end to log response
    const originalEnd = res.end;
    res.end = function (...args) {
      const duration = Date.now() - start;

      enhancedLogger.api(req.method, req.url, res.statusCode, duration, {
        requestId: req.id,
        ip: req.ip,
        userAgent: req.get("User-Agent"),
      });

      // Clear global context
      delete global.requestId;
      delete global.userId;

      originalEnd.apply(this, args);
    };

    next();
  };
}

/**
 * Error logging middleware
 */
function errorLogger() {
  return (error, req, res, next) => {
    enhancedLogger.error("Request Error", error, {
      method: req.method,
      url: req.url,
      requestId: req.id,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
    });

    next(error);
  };
}

/**
 * Log stream for Morgan integration
 */
const logStream = {
  write: (message) => {
    enhancedLogger.http(message.trim());
  },
};

module.exports = enhancedLogger;
module.exports.createRequestLogger = createRequestLogger;
module.exports.errorLogger = errorLogger;
module.exports.logStream = logStream;
module.exports.winston = logger;
