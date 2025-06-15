#!/usr/bin/env node

/**
 * Task Management API Server
 * Main entry point for the application
 */

// Load environment variables first
require('dotenv').config();

const http = require('http');
const app = require('./src/app');
const config = require('./src/config');
const logger = require('./src/utils/logger');
const { connectDatabase } = require('./src/config/database');
const { connectRedis } = require('./src/config/redis');

// Get port from environment
const PORT = config.port || 3000;
const NODE_ENV = config.nodeEnv || 'development';

/**
 * Create HTTP server
 */
const server = http.createServer(app);

/**
 * Initialize Socket.IO
 */
const { Server } = require('socket.io');
const io = new Server(server, {
  cors: {
    origin: config.socket.corsOrigin,
    methods: ['GET', 'POST']
  },
  pingTimeout: config.socket.pingTimeout,
  pingInterval: config.socket.pingInterval
});

// Attach socket.io to app for use in other modules
app.set('io', io);

// Initialize socket handlers
require('./src/websocket/socketHandlers')(io);

/**
 * Normalize port into a number, string, or false
 */
function normalizePort(val) {
  const port = parseInt(val, 10);
  
  if (isNaN(port)) {
    return val; // named pipe
  }
  
  if (port >= 0) {
    return port; // port number
  }
  
  return false;
}

/**
 * Event listener for HTTP server "error" event
 */
function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  const bind = typeof PORT === 'string' ? `Pipe ${PORT}` : `Port ${PORT}`;

  switch (error.code) {
    case 'EACCES':
      logger.error(`${bind} requires elevated privileges`);
      process.exit(1);
      break;
    case 'EADDRINUSE':
      logger.error(`${bind} is already in use`);
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * Event listener for HTTP server "listening" event
 */
function onListening() {
  const addr = server.address();
  const bind = typeof addr === 'string' ? `pipe ${addr}` : `port ${addr.port}`;
  
  logger.info(`🚀 Server listening on ${bind}`);
  logger.info(`📱 Environment: ${NODE_ENV}`);
  logger.info(`🌐 API Base URL: http://localhost:${addr.port}/api/${config.apiVersion}`);
  
  if (config.enableDocs) {
    logger.info(`📚 API Documentation: http://localhost:${addr.port}${config.docsPath}`);
  }
}

/**
 * Initialize database connections and start server
 */
async function startServer() {
  try {
    // Connect to MongoDB
    logger.info('🔌 Connecting to MongoDB...');
    await connectDatabase();
    logger.info('✅ MongoDB connected successfully');

    // Connect to Redis
    logger.info('🔌 Connecting to Redis...');
    await connectRedis();
    logger.info('✅ Redis connected successfully');

    // Configure server
    const normalizedPort = normalizePort(PORT);
    server.listen(normalizedPort);
    server.on('error', onError);
    server.on('listening', onListening);

  } catch (error) {
    logger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * Graceful shutdown handling
 */
function gracefulShutdown(signal) {
  logger.info(`🛑 Received ${signal}. Starting graceful shutdown...`);
  
  server.close(async (err) => {
    if (err) {
      logger.error('❌ Error during server shutdown:', err);
      process.exit(1);
    }

    try {
      // Close database connections
      const mongoose = require('mongoose');
      await mongoose.connection.close();
      logger.info('✅ MongoDB connection closed');

      // Close Redis connection
      const { getRedisClient } = require('./src/config/redis');
      const redisClient = getRedisClient();
      if (redisClient) {
        await redisClient.quit();
        logger.info('✅ Redis connection closed');
      }

      logger.info('✅ Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      logger.error('❌ Error during graceful shutdown:', error);
      process.exit(1);
    }
  });

  // Force close after 10 seconds
  setTimeout(() => {
    logger.error('❌ Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

/**
 * Handle uncaught exceptions and unhandled rejections
 */
process.on('uncaughtException', (error) => {
  logger.error('❌ Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('UNHANDLED_REJECTION');
});

// Graceful shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Health check for process managers
process.on('SIGUSR2', () => {
  logger.info('🔄 Received SIGUSR2 - Health check passed');
});

/**
 * Start the server
 */
if (require.main === module) {
  startServer();
}

module.exports = server;