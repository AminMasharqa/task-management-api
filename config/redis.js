/**
 * Redis Configuration
 * Redis connection management for caching, sessions, and real-time features
 */

const { createClient } = require('redis');
const config = require('./index');
const logger = require('../utils/logger');

/**
 * Redis client instances
 */
let redisClient = null;
let redisSubscriber = null;
let redisPublisher = null;

/**
 * Connection state tracking
 */
let isConnected = false;
let connectionAttempts = 0;
const maxRetries = 5;

/**
 * Create Redis client with configuration
 */
function createRedisClient(options = {}) {
  const clientConfig = {
    socket: {
      host: config.redis.host,
      port: config.redis.port,
      connectTimeout: 10000,
      commandTimeout: 5000,
      ...options.socket
    },
    password: config.redis.password || undefined,
    database: config.redis.db,
    ...options
  };

  // Remove empty password to avoid Redis auth errors
  if (!clientConfig.password) {
    delete clientConfig.password;
  }

  return createClient(clientConfig);
}

/**
 * Setup Redis event handlers
 */
function setupEventHandlers(client, clientType = 'main') {
  client.on('connect', () => {
    logger.info(`🔌 Redis ${clientType} client connecting...`);
  });

  client.on('ready', () => {
    isConnected = true;
    connectionAttempts = 0;
    logger.info(`✅ Redis ${clientType} client connected successfully`, {
      host: config.redis.host,
      port: config.redis.port,
      database: config.redis.db
    });
  });

  client.on('error', (error) => {
    isConnected = false;
    logger.error(`❌ Redis ${clientType} client error:`, error);
    
    // Handle specific error types
    if (error.code === 'ECONNREFUSED') {
      logger.error('🚫 Redis server is not running or unreachable');
    } else if (error.code === 'ENOTFOUND') {
      logger.error('🔍 Redis host not found');
    } else if (error.message.includes('WRONGPASS')) {
      logger.error('🔐 Redis authentication failed');
    }
  });

  client.on('end', () => {
    isConnected = false;
    logger.warn(`⚠️ Redis ${clientType} client connection ended`);
  });

  client.on('reconnecting', () => {
    connectionAttempts++;
    logger.info(`🔄 Redis ${clientType} client reconnecting... (attempt ${connectionAttempts})`);
    
    if (connectionAttempts >= maxRetries) {
      logger.error(`❌ Redis ${clientType} client max retry attempts reached`);
    }
  });
}

/**
 * Connect to Redis
 */
async function connectRedis() {
  try {
    logger.info('🔌 Connecting to Redis...', {
      host: config.redis.host,
      port: config.redis.port,
      database: config.redis.db
    });

    // Create main Redis client for general operations
    redisClient = createRedisClient();
    setupEventHandlers(redisClient, 'main');
    await redisClient.connect();

    // Create separate clients for pub/sub operations
    if (config.nodeEnv !== 'test') {
      redisSubscriber = createRedisClient();
      setupEventHandlers(redisSubscriber, 'subscriber');
      await redisSubscriber.connect();

      redisPublisher = createRedisClient();
      setupEventHandlers(redisPublisher, 'publisher');
      await redisPublisher.connect();
    }

    // Verify connection
    await verifyConnection();

    // Setup graceful shutdown
    setupGracefulShutdown();

    return redisClient;

  } catch (error) {
    logger.error('❌ Failed to connect to Redis:', error);
    throw error;
  }
}

/**
 * Verify Redis connection and perform health check
 */
async function verifyConnection() {
  try {
    const pong = await redisClient.ping();
    if (pong !== 'PONG') {
      throw new Error('Redis ping failed');
    }

    // Test basic operations
    await redisClient.set('health:check', 'ok', { EX: 10 });
    const value = await redisClient.get('health:check');
    
    if (value !== 'ok') {
      throw new Error('Redis read/write test failed');
    }

    await redisClient.del('health:check');
    logger.info('🏥 Redis health check passed');
    
    return true;
  } catch (error) {
    logger.error('❌ Redis health check failed:', error);
    throw error;
  }
}

/**
 * Get Redis connection status
 */
function getConnectionStatus() {
  return {
    isConnected,
    connectionAttempts,
    clients: {
      main: redisClient?.isReady || false,
      subscriber: redisSubscriber?.isReady || false,
      publisher: redisPublisher?.isReady || false
    },
    config: {
      host: config.redis.host,
      port: config.redis.port,
      database: config.redis.db
    }
  };
}

/**
 * Cache operations with error handling
 */
const cache = {
  /**
   * Set cache value with TTL
   */
  async set(key, value, ttl = config.redis.ttl) {
    try {
      if (!redisClient?.isReady) {
        logger.warn('Redis not available, skipping cache set');
        return false;
      }

      const serializedValue = JSON.stringify(value);
      await redisClient.setEx(key, ttl, serializedValue);
      
      logger.debug(`📝 Cache set: ${key}`, { ttl });
      return true;
    } catch (error) {
      logger.error('❌ Cache set error:', error);
      return false;
    }
  },

  /**
   * Get cache value
   */
  async get(key) {
    try {
      if (!redisClient?.isReady) {
        logger.warn('Redis not available, cache miss');
        return null;
      }

      const value = await redisClient.get(key);
      if (!value) {
        logger.debug(`🔍 Cache miss: ${key}`);
        return null;
      }

      logger.debug(`✅ Cache hit: ${key}`);
      return JSON.parse(value);
    } catch (error) {
      logger.error('❌ Cache get error:', error);
      return null;
    }
  },

  /**
   * Delete cache value
   */
  async del(key) {
    try {
      if (!redisClient?.isReady) {
        logger.warn('Redis not available, skipping cache delete');
        return false;
      }

      const result = await redisClient.del(key);
      logger.debug(`🗑️ Cache deleted: ${key}`);
      return result > 0;
    } catch (error) {
      logger.error('❌ Cache delete error:', error);
      return false;
    }
  },

  /**
   * Check if key exists
   */
  async exists(key) {
    try {
      if (!redisClient?.isReady) {
        return false;
      }

      return await redisClient.exists(key) === 1;
    } catch (error) {
      logger.error('❌ Cache exists error:', error);
      return false;
    }
  },

  /**
   * Increment counter
   */
  async incr(key, ttl = config.redis.ttl) {
    try {
      if (!redisClient?.isReady) {
        logger.warn('Redis not available, skipping increment');
        return 0;
      }

      const value = await redisClient.incr(key);
      
      // Set TTL only on first increment
      if (value === 1 && ttl > 0) {
        await redisClient.expire(key, ttl);
      }

      return value;
    } catch (error) {
      logger.error('❌ Cache increment error:', error);
      return 0;
    }
  },

  /**
   * Clear cache by pattern
   */
  async clearPattern(pattern) {
    try {
      if (!redisClient?.isReady) {
        logger.warn('Redis not available, skipping pattern clear');
        return 0;
      }

      const keys = await redisClient.keys(pattern);
      if (keys.length === 0) {
        return 0;
      }

      const result = await redisClient.del(keys);
      logger.info(`🧹 Cleared ${result} cache entries matching: ${pattern}`);
      return result;
    } catch (error) {
      logger.error('❌ Cache pattern clear error:', error);
      return 0;
    }
  }
};

/**
 * Pub/Sub operations
 */
const pubsub = {
  /**
   * Publish message to channel
   */
  async publish(channel, data) {
    try {
      if (!redisPublisher?.isReady) {
        logger.warn('Redis publisher not available');
        return false;
      }

      const message = JSON.stringify(data);
      await redisPublisher.publish(channel, message);
      
      logger.debug(`📢 Published to ${channel}:`, data);
      return true;
    } catch (error) {
      logger.error('❌ Publish error:', error);
      return false;
    }
  },

  /**
   * Subscribe to channel
   */
  async subscribe(channel, callback) {
    try {
      if (!redisSubscriber?.isReady) {
        logger.warn('Redis subscriber not available');
        return false;
      }

      await redisSubscriber.subscribe(channel, (message) => {
        try {
          const data = JSON.parse(message);
          callback(data);
          logger.debug(`📨 Received from ${channel}:`, data);
        } catch (error) {
          logger.error('❌ Message parse error:', error);
        }
      });

      logger.info(`👂 Subscribed to channel: ${channel}`);
      return true;
    } catch (error) {
      logger.error('❌ Subscribe error:', error);
      return false;
    }
  },

  /**
   * Unsubscribe from channel
   */
  async unsubscribe(channel) {
    try {
      if (!redisSubscriber?.isReady) {
        return false;
      }

      await redisSubscriber.unsubscribe(channel);
      logger.info(`🔇 Unsubscribed from channel: ${channel}`);
      return true;
    } catch (error) {
      logger.error('❌ Unsubscribe error:', error);
      return false;
    }
  }
};

/**
 * Get Redis statistics
 */
async function getRedisStats() {
  try {
    if (!redisClient?.isReady) {
      throw new Error('Redis not connected');
    }

    const info = await redisClient.info();
    const memory = await redisClient.info('memory');
    const stats = await redisClient.info('stats');

    return {
      version: info.match(/redis_version:([^\r\n]*)/)?.[1],
      uptime: info.match(/uptime_in_seconds:([^\r\n]*)/)?.[1],
      connectedClients: info.match(/connected_clients:([^\r\n]*)/)?.[1],
      usedMemory: memory.match(/used_memory_human:([^\r\n]*)/)?.[1],
      totalCommands: stats.match(/total_commands_processed:([^\r\n]*)/)?.[1],
      keyspaceHits: stats.match(/keyspace_hits:([^\r\n]*)/)?.[1],
      keyspaceMisses: stats.match(/keyspace_misses:([^\r\n]*)/)?.[1]
    };
  } catch (error) {
    logger.error('❌ Failed to get Redis stats:', error);
    throw error;
  }
}

/**
 * Setup graceful shutdown
 */
function setupGracefulShutdown() {
  const shutdown = async (signal) => {
    logger.info(`🛑 Received ${signal}. Closing Redis connections...`);
    
    try {
      const promises = [];
      
      if (redisClient?.isReady) {
        promises.push(redisClient.quit());
      }
      if (redisSubscriber?.isReady) {
        promises.push(redisSubscriber.quit());
      }
      if (redisPublisher?.isReady) {
        promises.push(redisPublisher.quit());
      }

      await Promise.all(promises);
      logger.info('✅ Redis connections closed gracefully');
    } catch (error) {
      logger.error('❌ Error closing Redis connections:', error);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

/**
 * Health check function
 */
async function healthCheck() {
  try {
    const status = getConnectionStatus();
    
    if (!status.isConnected) {
      throw new Error('Redis not connected');
    }

    await redisClient.ping();
    
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      connection: status
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error.message
    };
  }
}

/**
 * Get Redis client (for advanced operations)
 */
function getRedisClient() {
  return redisClient;
}

module.exports = {
  connectRedis,
  getConnectionStatus,
  getRedisStats,
  healthCheck,
  cache,
  pubsub,
  getRedisClient
};