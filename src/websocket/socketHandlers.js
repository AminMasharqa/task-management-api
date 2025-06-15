/**
 * WebSocket Handlers
 * Real-time collaboration and notifications
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { pubsub } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Authenticate socket connection
 */
const authenticateSocket = async (socket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    
    if (!token) {
      return next(new Error('Authentication token required'));
    }

    const decoded = jwt.verify(token, config.jwt.secret);
    const user = await User.findById(decoded.userId).select('firstName lastName email username role isActive');

    if (!user || !user.isActive) {
      return next(new Error('User not found or inactive'));
    }

    socket.userId = user._id.toString();
    socket.user = user;
    
    logger.info('Socket authenticated', { userId: socket.userId, socketId: socket.id });
    next();

  } catch (error) {
    logger.warn('Socket authentication failed', { error: error.message });
    next(new Error('Authentication failed'));
  }
};

/**
 * Handle user connection
 */
const handleConnection = (socket) => {
  logger.info('User connected via WebSocket', { 
    userId: socket.userId, 
    socketId: socket.id 
  });

  // Join user-specific room for notifications
  socket.join(`user:${socket.userId}`);

  // Send welcome message
  socket.emit('connected', {
    message: 'Connected successfully',
    userId: socket.userId,
    timestamp: new Date()
  });

  // Handle task updates
  socket.on('join_task', (taskId) => {
    socket.join(`task:${taskId}`);
    logger.debug('User joined task room', { userId: socket.userId, taskId });
  });

  socket.on('leave_task', (taskId) => {
    socket.leave(`task:${taskId}`);
    logger.debug('User left task room', { userId: socket.userId, taskId });
  });

  // Handle typing indicators for comments
  socket.on('typing_start', (data) => {
    socket.to(`task:${data.taskId}`).emit('user_typing', {
      userId: socket.userId,
      userName: socket.user.firstName + ' ' + socket.user.lastName,
      taskId: data.taskId
    });
  });

  socket.on('typing_stop', (data) => {
    socket.to(`task:${data.taskId}`).emit('user_stopped_typing', {
      userId: socket.userId,
      taskId: data.taskId
    });
  });

  // Handle user presence
  socket.on('user_status', (status) => {
    socket.broadcast.emit('user_status_changed', {
      userId: socket.userId,
      status,
      timestamp: new Date()
    });
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    logger.info('User disconnected', { 
      userId: socket.userId, 
      socketId: socket.id 
    });

    // Notify others user went offline
    socket.broadcast.emit('user_offline', {
      userId: socket.userId,
      timestamp: new Date()
    });
  });

  // Error handling
  socket.on('error', (error) => {
    logger.error('Socket error', error, { userId: socket.userId });
  });
};

/**
 * Subscribe to Redis pub/sub for cross-server communication
 */
const setupPubSubHandlers = (io) => {
  // Task updates
  pubsub.subscribe('task:created', (data) => {
    io.emit('task_created', data);
  });

  pubsub.subscribe('task:updated', (data) => {
    io.to(`task:${data.task.id}`).emit('task_updated', data);
  });

  pubsub.subscribe('task:deleted', (data) => {
    io.to(`task:${data.taskId}`).emit('task_deleted', data);
  });

  pubsub.subscribe('task:status_changed', (data) => {
    io.to(`task:${data.taskId}`).emit('task_status_changed', data);
  });

  // User notifications
  pubsub.subscribe('notifications:new', (data) => {
    io.to(`user:${data.userId}`).emit('notification', data.notification);
  });

  logger.info('✅ WebSocket pub/sub handlers configured');
};

/**
 * Initialize WebSocket server
 */
const initializeWebSocket = (io) => {
  // Authentication middleware
  io.use(authenticateSocket);

  // Connection handler
  io.on('connection', handleConnection);

  // Setup pub/sub
  setupPubSubHandlers(io);

  logger.info('✅ WebSocket server initialized');
};

module.exports = initializeWebSocket;