/**
 * Test Setup
 * Configuration for Jest testing environment
 */

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const redis = require('redis');
const config = require('../src/config');

// Test database instance
let mongod;
let redisClient;

/**
 * Setup test environment before all tests
 */
beforeAll(async () => {
  // Set test environment
  process.env.NODE_ENV = 'test';
  
  // Start in-memory MongoDB
  mongod = await MongoMemoryServer.create();
  const mongoUri = mongod.getUri();
  
  // Connect to test database
  await mongoose.connect(mongoUri, {
    maxPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  });

  // Setup Redis mock for tests
  const redisMock = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    exists: jest.fn().mockResolvedValue(0),
    incr: jest.fn().mockResolvedValue(1),
    keys: jest.fn().mockResolvedValue([]),
    clearPattern: jest.fn().mockResolvedValue(0),
    quit: jest.fn().mockResolvedValue('OK')
  };

  // Mock Redis client
  jest.doMock('../src/config/redis', () => ({
    cache: redisMock,
    pubsub: {
      publish: jest.fn().mockResolvedValue(0),
      subscribe: jest.fn().mockResolvedValue(true)
    },
    connectRedis: jest.fn().mockResolvedValue(redisMock),
    getRedisClient: jest.fn().mockReturnValue(redisMock)
  }));

  // Mock email service
  jest.doMock('nodemailer', () => ({
    createTransporter: jest.fn().mockReturnValue({
      sendMail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' }),
      verify: jest.fn().mockResolvedValue(true)
    })
  }));

  // Disable console.log in tests
  if (!process.env.ENABLE_TEST_LOGS) {
    console.log = jest.fn();
    console.info = jest.fn();
    console.warn = jest.fn();
  }

  console.log('✅ Test environment setup complete');
});

/**
 * Cleanup after each test
 */
afterEach(async () => {
  // Clear all collections
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }

  // Clear all mocks
  jest.clearAllMocks();
});

/**
 * Cleanup after all tests
 */
afterAll(async () => {
  // Close database connection
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
  
  // Stop MongoDB instance
  if (mongod) {
    await mongod.stop();
  }

  console.log('✅ Test environment cleanup complete');
});

/**
 * Test utilities
 */
global.testUtils = {
  /**
   * Create test user
   */
  createTestUser: async (userData = {}) => {
    const User = require('../src/models/User');
    const bcrypt = require('bcryptjs');
    
    const defaultUser = {
      email: 'test@example.com',
      username: 'testuser',
      password: await bcrypt.hash('Test123!', 10),
      firstName: 'Test',
      lastName: 'User',
      emailVerified: true,
      role: 'user',
      ...userData
    };

    return await User.create(defaultUser);
  },

  /**
   * Create test admin user
   */
  createTestAdmin: async (userData = {}) => {
    return await global.testUtils.createTestUser({
      email: 'admin@example.com',
      username: 'adminuser',
      role: 'admin',
      ...userData
    });
  },

  /**
   * Create test task
   */
  createTestTask: async (taskData = {}, createdBy) => {
    const Task = require('../src/models/Task');
    
    const defaultTask = {
      title: 'Test Task',
      description: 'Test task description',
      status: 'todo',
      priority: 'medium',
      createdBy: createdBy._id,
      ...taskData
    };

    return await Task.create(defaultTask);
  },

  /**
   * Generate JWT token for testing
   */
  generateTestToken: (user) => {
    const jwt = require('jsonwebtoken');
    return jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role,
        type: 'access'
      },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '1h' }
    );
  },

  /**
   * Make authenticated request helper
   */
  authenticatedRequest: (app, user) => {
    const request = require('supertest');
    const token = global.testUtils.generateTestToken(user);
    
    return {
      get: (url) => request(app).get(url).set('Authorization', `Bearer ${token}`),
      post: (url) => request(app).post(url).set('Authorization', `Bearer ${token}`),
      put: (url) => request(app).put(url).set('Authorization', `Bearer ${token}`),
      delete: (url) => request(app).delete(url).set('Authorization', `Bearer ${token}`),
      patch: (url) => request(app).patch(url).set('Authorization', `Bearer ${token}`)
    };
  },

  /**
   * Wait for async operations
   */
  waitFor: (ms) => new Promise(resolve => setTimeout(resolve, ms)),

  /**
   * Mock file upload
   */
  mockFile: (filename = 'test.jpg', mimetype = 'image/jpeg', size = 1024) => ({
    fieldname: 'file',
    originalname: filename,
    encoding: '7bit',
    mimetype,
    size,
    buffer: Buffer.from('mock file content'),
    destination: '/tmp',
    filename: `test-${Date.now()}-${filename}`,
    path: `/tmp/test-${Date.now()}-${filename}`
  }),

  /**
   * Assert array contains object with properties
   */
  expectArrayToContainObject: (array, expectedObject) => {
    const found = array.find(item => {
      return Object.keys(expectedObject).every(key => 
        item[key] === expectedObject[key]
      );
    });
    expect(found).toBeDefined();
    return found;
  },

  /**
   * Assert response has standard API format
   */
  expectStandardResponse: (response, expectedStatus = 200) => {
    expect(response.status).toBe(expectedStatus);
    expect(response.body).toHaveProperty('success');
    
    if (expectedStatus >= 200 && expectedStatus < 300) {
      expect(response.body.success).toBe(true);
      expect(response.body).toHaveProperty('data');
    } else {
      expect(response.body.success).toBe(false);
      expect(response.body).toHaveProperty('message');
    }
  },

  /**
   * Clean database collections
   */
  cleanDatabase: async () => {
    const collections = mongoose.connection.collections;
    for (const key in collections) {
      await collections[key].deleteMany({});
    }
  }
};

/**
 * Custom Jest matchers
 */
expect.extend({
  toBeValidObjectId(received) {
    const mongoose = require('mongoose');
    const pass = mongoose.Types.ObjectId.isValid(received);
    
    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid ObjectId`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid ObjectId`,
        pass: false,
      };
    }
  },

  toHaveValidationError(received, field) {
    const hasValidationError = received.body && 
                              received.body.errors && 
                              received.body.errors.some(error => error.field === field);
    
    if (hasValidationError) {
      return {
        message: () => `expected response not to have validation error for field ${field}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected response to have validation error for field ${field}`,
        pass: false,
      };
    }
  }
});

/**
 * Global test timeout
 */
jest.setTimeout(30000);

/**
 * Suppress console errors in tests unless explicitly enabled
 */
if (!process.env.ENABLE_TEST_LOGS) {
  const originalError = console.error;
  console.error = (...args) => {
    if (typeof args[0] === 'string' && args[0].includes('Warning:')) {
      return;
    }
    originalError.call(console, ...args);
  };
}

module.exports = {
  testUtils: global.testUtils
};