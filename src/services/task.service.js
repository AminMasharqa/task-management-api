/**
 * Task Service
 * Business logic for task operations
 */

const Task = require('../models/Task');
const User = require('../models/User');
const { cache } = require('../config/redis');
const logger = require('../utils/logger');

/**
 * Get tasks with advanced filtering
 */
const getTasksWithFilters = async (filters, userId, userRole) => {
  try {
    const query = { isDeleted: false };

    // Apply user access control
    if (!['admin', 'manager'].includes(userRole)) {
      query.$or = [
        { createdBy: userId },
        { assignedTo: userId },
        { collaborators: userId }
      ];
    }

    // Apply filters
    if (filters.status) query.status = filters.status;
    if (filters.priority) query.priority = filters.priority;
    if (filters.assignedTo) query.assignedTo = filters.assignedTo;
    if (filters.createdBy) query.createdBy = filters.createdBy;
    if (filters.tags) query.tags = { $in: filters.tags };
    
    if (filters.dueBefore || filters.dueAfter) {
      query.dueDate = {};
      if (filters.dueBefore) query.dueDate.$lte = new Date(filters.dueBefore);
      if (filters.dueAfter) query.dueDate.$gte = new Date(filters.dueAfter);
    }

    return query;
  } catch (error) {
    logger.error('Error building task filters', error);
    throw error;
  }
};

/**
 * Calculate task analytics
 */
const calculateTaskAnalytics = async (userId, timeframe = '30d') => {
  try {
    const days = parseInt(timeframe.replace('d', ''));
    const dateFrom = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const pipeline = [
      {
        $match: {
          $or: [{ createdBy: userId }, { assignedTo: userId }],
          createdAt: { $gte: dateFrom },
          isDeleted: false
        }
      },
      {
        $group: {
          _id: null,
          totalTasks: { $sum: 1 },
          completedTasks: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
          inProgressTasks: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } },
          avgProgress: { $avg: '$progress' },
          totalTimeSpent: { $sum: '$actualHours' }
        }
      }
    ];

    const result = await Task.aggregate(pipeline);
    return result[0] || {
      totalTasks: 0,
      completedTasks: 0,
      inProgressTasks: 0,
      avgProgress: 0,
      totalTimeSpent: 0
    };
  } catch (error) {
    logger.error('Error calculating task analytics', error);
    throw error;
  }
};

/**
 * Get overdue tasks
 */
const getOverdueTasks = async (userId) => {
  try {
    const cacheKey = `overdue_tasks:${userId}`;
    const cached = await cache.get(cacheKey);
    
    if (cached) return cached;

    const overdueTasks = await Task.find({
      $or: [{ createdBy: userId }, { assignedTo: userId }],
      dueDate: { $lt: new Date() },
      status: { $nin: ['completed', 'cancelled'] },
      isDeleted: false
    })
    .populate('assignedTo', 'firstName lastName')
    .select('title dueDate priority status')
    .sort({ dueDate: 1 })
    .lean();

    await cache.set(cacheKey, overdueTasks, 300); // 5 minutes
    return overdueTasks;
  } catch (error) {
    logger.error('Error getting overdue tasks', error);
    throw error;
  }
};

/**
 * Bulk update task status
 */
const bulkUpdateStatus = async (taskIds, status, userId) => {
  try {
    const result = await Task.updateMany(
      {
        _id: { $in: taskIds },
        $or: [
          { createdBy: userId },
          { assignedTo: userId }
        ]
      },
      {
        status,
        updatedBy: userId,
        ...(status === 'completed' && { completedAt: new Date(), completedBy: userId })
      }
    );

    logger.business('Bulk status update', {
      taskIds,
      status,
      updatedBy: userId,
      modifiedCount: result.modifiedCount
    });

    return result;
  } catch (error) {
    logger.error('Error in bulk status update', error);
    throw error;
  }
};

/**
 * Get task completion trend
 */
const getCompletionTrend = async (userId, days = 30) => {
  try {
    const dateFrom = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const pipeline = [
      {
        $match: {
          $or: [{ createdBy: userId }, { assignedTo: userId }],
          completedAt: { $gte: dateFrom },
          status: 'completed',
          isDeleted: false
        }
      },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$completedAt' } }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.date': 1 } }
    ];

    const trend = await Task.aggregate(pipeline);
    return trend.map(item => ({
      date: item._id.date,
      completed: item.count
    }));
  } catch (error) {
    logger.error('Error getting completion trend', error);
    throw error;
  }
};

/**
 * Validate task assignment
 */
const validateAssignment = async (taskId, userIds) => {
  try {
    // Check if users exist and are active
    const users = await User.find({
      _id: { $in: userIds },
      isActive: true
    }).select('_id');

    const validUserIds = users.map(u => u._id.toString());
    const invalidUserIds = userIds.filter(id => !validUserIds.includes(id));

    if (invalidUserIds.length > 0) {
      throw new Error(`Invalid user IDs: ${invalidUserIds.join(', ')}`);
    }

    // Check if task exists
    const task = await Task.findById(taskId).select('_id');
    if (!task) {
      throw new Error('Task not found');
    }

    return { valid: true, users: validUserIds };
  } catch (error) {
    logger.error('Error validating task assignment', error);
    throw error;
  }
};

module.exports = {
  getTasksWithFilters,
  calculateTaskAnalytics,
  getOverdueTasks,
  bulkUpdateStatus,
  getCompletionTrend,
  validateAssignment
};