/**
 * Database Configuration
 * MongoDB connection management with Mongoose
 */

const mongoose = require('mongoose');
const config = require('./index');
const logger = require('../utils/logger');

/**
 * Database connection state
 */
let isConnected = false;

/**
 * Configure Mongoose settings
 */
function configureMongoose() {
  // Enable strict mode for queries
  mongoose.set('strictQuery', true);
  
  // Enable strict mode for population
  mongoose.set('strictPopulate', true);

  // Disable automatic index creation in production
  if (config.isProduction()) {
    mongoose.set('autoIndex', false);
  }

  // Enable debug mode in development
  if (config.development.debugDbQueries) {
    mongoose.set('debug', (collectionName, method, query, doc) => {
      logger.debug('Mongoose Debug:', {
        collection: collectionName,
        method,
        query,
        doc
      });
    });
  }
}

/**
 * Database event handlers
 */
function setupEventHandlers() {
  // Connection successful
  mongoose.connection.on('connected', () => {
    isConnected = true;
    logger.info('✅ MongoDB connected successfully', {
      host: mongoose.connection.host,
      port: mongoose.connection.port,
      database: mongoose.connection.name
    });
  });

  // Connection error
  mongoose.connection.on('error', (error) => {
    isConnected = false;
    logger.error('❌ MongoDB connection error:', error);
  });

  // Disconnected
  mongoose.connection.on('disconnected', () => {
    isConnected = false;
    logger.warn('⚠️ MongoDB disconnected');
  });

  // Reconnected
  mongoose.connection.on('reconnected', () => {
    isConnected = true;
    logger.info('🔄 MongoDB reconnected');
  });

  // Connection timeout
  mongoose.connection.on('timeout', () => {
    logger.warn('⏰ MongoDB connection timeout');
  });

  // Full setup (indexes created)
  mongoose.connection.on('index', (error) => {
    if (error) {
      logger.error('❌ MongoDB index error:', error);
    } else {
      logger.info('📝 MongoDB indexes created successfully');
    }
  });

  // Process termination handlers
  process.on('SIGINT', gracefulShutdown);
  process.on('SIGTERM', gracefulShutdown);
}

/**
 * Graceful shutdown of database connection
 */
async function gracefulShutdown(signal) {
  if (signal) {
    logger.info(`🛑 Received ${signal}. Closing MongoDB connection...`);
  }

  try {
    await mongoose.connection.close();
    logger.info('✅ MongoDB connection closed gracefully');
  } catch (error) {
    logger.error('❌ Error closing MongoDB connection:', error);
  }
}

/**
 * Connect to MongoDB
 */
async function connectDatabase() {
  try {
    // Configure Mongoose before connecting
    configureMongoose();
    
    // Setup event handlers
    setupEventHandlers();

    const dbOptions = {
      ...config.database.options,
      // Connection name for debugging
      dbName: getDatabaseName(config.database.uri),
    };

    logger.info('🔌 Connecting to MongoDB...', {
      uri: maskConnectionString(config.database.uri),
      options: {
        maxPoolSize: dbOptions.maxPoolSize,
        minPoolSize: dbOptions.minPoolSize
      }
    });

    // Connect to MongoDB
    await mongoose.connect(config.database.uri, dbOptions);

    // Verify connection
    await verifyConnection();

    return mongoose.connection;

  } catch (error) {
    logger.error('❌ Failed to connect to MongoDB:', error);
    throw error;
  }
}

/**
 * Verify database connection and perform health check
 */
async function verifyConnection() {
  try {
    // Check if we can perform a simple operation
    const admin = mongoose.connection.db.admin();
    await admin.ping();
    
    logger.info('🏥 Database health check passed');
    return true;
  } catch (error) {
    logger.error('❌ Database health check failed:', error);
    throw error;
  }
}

/**
 * Get database connection status
 */
function getConnectionStatus() {
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };

  return {
    isConnected,
    state: states[mongoose.connection.readyState] || 'unknown',
    host: mongoose.connection.host,
    port: mongoose.connection.port,
    name: mongoose.connection.name,
    collections: Object.keys(mongoose.connection.collections)
  };
}

/**
 * Create database indexes
 */
async function createIndexes() {
  try {
    logger.info('📝 Creating database indexes...');
    
    // Get all models
    const models = mongoose.modelNames();
    
    for (const modelName of models) {
      const model = mongoose.model(modelName);
      
      // Ensure indexes for this model
      await model.createIndexes();
      logger.debug(`✅ Indexes created for ${modelName}`);
    }
    
    logger.info('✅ All database indexes created successfully');
  } catch (error) {
    logger.error('❌ Failed to create database indexes:', error);
    throw error;
  }
}

/**
 * Drop database (use with caution!)
 */
async function dropDatabase() {
  if (config.isProduction()) {
    throw new Error('Cannot drop database in production environment');
  }

  try {
    logger.warn('⚠️ Dropping database...');
    await mongoose.connection.dropDatabase();
    logger.info('✅ Database dropped successfully');
  } catch (error) {
    logger.error('❌ Failed to drop database:', error);
    throw error;
  }
}

/**
 * Get database statistics
 */
async function getDatabaseStats() {
  try {
    const db = mongoose.connection.db;
    const stats = await db.stats();
    
    return {
      database: stats.db,
      collections: stats.collections,
      documents: stats.objects,
      dataSize: formatBytes(stats.dataSize),
      storageSize: formatBytes(stats.storageSize),
      indexes: stats.indexes,
      indexSize: formatBytes(stats.indexSize),
      avgObjSize: formatBytes(stats.avgObjSize)
    };
  } catch (error) {
    logger.error('❌ Failed to get database stats:', error);
    throw error;
  }
}

/**
 * Utility functions
 */

// Extract database name from connection URI
function getDatabaseName(uri) {
  try {
    const url = new URL(uri);
    return url.pathname.slice(1) || 'test';
  } catch {
    return 'task_management';
  }
}

// Mask connection string for logging (hide password)
function maskConnectionString(uri) {
  try {
    const url = new URL(uri);
    if (url.password) {
      url.password = '***';
    }
    return url.toString();
  } catch {
    return uri.replace(/:([^:@]+)@/, ':***@');
  }
}

// Format bytes to human readable format
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Health check function for monitoring
 */
async function healthCheck() {
  try {
    const status = getConnectionStatus();
    
    if (!status.isConnected) {
      throw new Error('Database not connected');
    }

    // Perform a simple ping
    await mongoose.connection.db.admin().ping();
    
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      connection: status,
      uptime: process.uptime()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error.message
    };
  }
}

module.exports = {
  connectDatabase,
  gracefulShutdown,
  verifyConnection,
  getConnectionStatus,
  createIndexes,
  dropDatabase,
  getDatabaseStats,
  healthCheck,
  // For testing purposes
  mongoose
};