/**
 * Task Events
 * Event-driven task operations and side effects
 */

const EventEmitter = require('events');
const User = require('../models/User');
const notificationService = require('../services/notification.service');
const { pubsub, cache } = require('../config/redis');
const { TASK_STATUS, NOTIFICATION_TYPES } = require('../utils/constants');
const logger = require('../utils/logger');

class TaskEventEmitter extends EventEmitter {}
const taskEvents = new TaskEventEmitter();

/**
 * Task Created Event
 */
taskEvents.on('task:created', async (task, creator) => {
  try {
    logger.business('Task created event triggered', {
      taskId: task._id,
      createdBy: creator.id,
      title: task.title
    });

    // Update creator's task count
    await User.findByIdAndUpdate(creator.id, {
      $inc: { tasksCreated: 1 }
    });

    // Send notifications to assigned users
    if (task.assignedTo && task.assignedTo.length > 0) {
      await notificationService.notifyTaskAssignment(task, creator);
    }

    // Publish to WebSocket
    await pubsub.publish('task:created', {
      task: task.toObject(),
      createdBy: creator
    });

    // Clear relevant caches
    await clearTaskCaches(task, creator.id);

  } catch (error) {
    logger.error('Error handling task created event', error, {
      taskId: task._id
    });
  }
});

/**
 * Task Updated Event
 */
taskEvents.on('task:updated', async (task, updater, changes) => {
  try {
    logger.business('Task updated event triggered', {
      taskId: task._id,
      updatedBy: updater.id,
      changes: Object.keys(changes)
    });

    // Send notifications for significant changes
    const significantChanges = ['status', 'priority', 'assignedTo', 'dueDate'];
    const hasSignificantChanges = Object.keys(changes).some(key => 
      significantChanges.includes(key)
    );

    if (hasSignificantChanges) {
      await notificationService.notifyTaskUpdate(task, updater, changes);
    }

    // Handle status-specific events
    if (changes.status) {
      taskEvents.emit('task:status_changed', task, updater, changes.status.to);
    }

    // Handle assignment changes
    if (changes.assignedTo) {
      taskEvents.emit('task:assigned', task, updater, changes.assignedTo);
    }

    // Publish to WebSocket
    await pubsub.publish('task:updated', {
      task: task.toObject(),
      changes,
      updatedBy: updater
    });

    // Clear relevant caches
    await clearTaskCaches(task, updater.id);

  } catch (error) {
    logger.error('Error handling task updated event', error, {
      taskId: task._id
    });
  }
});

/**
 * Task Status Changed Event
 */
taskEvents.on('task:status_changed', async (task, updater, newStatus) => {
  try {
    logger.business('Task status changed', {
      taskId: task._id,
      oldStatus: task.status,
      newStatus,
      updatedBy: updater.id
    });

    // Handle completion
    if (newStatus === TASK_STATUS.COMPLETED) {
      taskEvents.emit('task:completed', task, updater);
    }

    // Send status change notifications
    await notificationService.notifyStatusChange(task, updater, newStatus);

    // Publish to WebSocket
    await pubsub.publish('task:status_changed', {
      taskId: task._id,
      status: newStatus,
      changedBy: updater
    });

  } catch (error) {
    logger.error('Error handling task status changed event', error, {
      taskId: task._id
    });
  }
});

/**
 * Task Completed Event
 */
taskEvents.on('task:completed', async (task, completer) => {
  try {
    logger.business('Task completed event triggered', {
      taskId: task._id,
      completedBy: completer.id,
      title: task.title
    });

    // Update completer's stats
    await User.findByIdAndUpdate(completer.id, {
      $inc: { tasksCompleted: 1 }
    });

    // Update creator's stats if different from completer
    if (task.createdBy.toString() !== completer.id) {
      await User.findByIdAndUpdate(task.createdBy, {
        $inc: { tasksCompleted: 1 }
      });
    }

    // Send completion notifications
    await notificationService.notifyTaskCompletion(task, completer);

    // Analytics event
    taskEvents.emit('analytics:task_completed', {
      taskId: task._id,
      createdBy: task.createdBy,
      completedBy: completer.id,
      timeTaken: task.completedAt - task.createdAt,
      priority: task.priority
    });

  } catch (error) {
    logger.error('Error handling task completed event', error, {
      taskId: task._id
    });
  }
});

/**
 * Task Assigned Event
 */
taskEvents.on('task:assigned', async (task, assigner, assignmentChanges) => {
  try {
    const { to: newAssignees, from: oldAssignees } = assignmentChanges;
    
    logger.business('Task assignment changed', {
      taskId: task._id,
      assignedBy: assigner.id,
      newAssignees,
      oldAssignees
    });

    // Find newly assigned users
    const addedAssignees = newAssignees.filter(id => 
      !oldAssignees.includes(id)
    );

    // Send notifications to newly assigned users
    if (addedAssignees.length > 0) {
      const taskWithNewAssignees = {
        ...task.toObject(),
        assignedTo: await User.find({ _id: { $in: addedAssignees } })
          .select('firstName lastName email')
      };
      
      await notificationService.notifyTaskAssignment(taskWithNewAssignees, assigner);
    }

  } catch (error) {
    logger.error('Error handling task assigned event', error, {
      taskId: task._id
    });
  }
});

/**
 * Task Deleted Event
 */
taskEvents.on('task:deleted', async (task, deleter) => {
  try {
    logger.business('Task deleted event triggered', {
      taskId: task._id,
      deletedBy: deleter.id,
      title: task.title
    });

    // Send deletion notifications
    await notificationService.notifyTaskDeletion(task, deleter);

    // Publish to WebSocket
    await pubsub.publish('task:deleted', {
      taskId: task._id,
      deletedBy: deleter
    });

    // Clear caches
    await clearTaskCaches(task, deleter.id);

  } catch (error) {
    logger.error('Error handling task deleted event', error, {
      taskId: task._id
    });
  }
});

/**
 * Task Comment Added Event
 */
taskEvents.on('task:comment_added', async (task, comment, author) => {
  try {
    logger.business('Task comment added', {
      taskId: task._id,
      commentId: comment._id,
      authorId: author.id
    });

    // Notify mentioned users
    if (comment.mentions && comment.mentions.length > 0) {
      for (const mentionedUserId of comment.mentions) {
        await notificationService.sendRealTimeNotification(
          mentionedUserId,
          NOTIFICATION_TYPES.MENTION,
          {
            task: { id: task._id, title: task.title },
            comment: { id: comment._id, content: comment.content },
            author: { id: author.id, name: author.firstName + ' ' + author.lastName }
          }
        );
      }
    }

    // Notify task stakeholders (excluding comment author)
    const stakeholders = new Set();
    if (task.createdBy.toString() !== author.id) {
      stakeholders.add(task.createdBy.toString());
    }
    
    task.assignedTo?.forEach(userId => {
      if (userId.toString() !== author.id) {
        stakeholders.add(userId.toString());
      }
    });

    for (const userId of stakeholders) {
      await notificationService.sendRealTimeNotification(
        userId,
        NOTIFICATION_TYPES.COMMENT_ADDED,
        {
          task: { id: task._id, title: task.title },
          comment: { content: comment.content },
          author: { id: author.id, name: author.firstName + ' ' + author.lastName }
        }
      );
    }

  } catch (error) {
    logger.error('Error handling comment added event', error, {
      taskId: task._id,
      commentId: comment._id
    });
  }
});

/**
 * Task Overdue Event
 */
taskEvents.on('task:overdue', async (task) => {
  try {
    logger.business('Task overdue event triggered', {
      taskId: task._id,
      dueDate: task.dueDate,
      title: task.title
    });

    // Notify assigned users and creator
    const notifyUsers = new Set([task.createdBy.toString()]);
    task.assignedTo?.forEach(userId => notifyUsers.add(userId.toString()));

    for (const userId of notifyUsers) {
      await notificationService.sendRealTimeNotification(
        userId,
        NOTIFICATION_TYPES.TASK_OVERDUE,
        {
          task: {
            id: task._id,
            title: task.title,
            dueDate: task.dueDate,
            priority: task.priority
          }
        }
      );
    }

  } catch (error) {
    logger.error('Error handling task overdue event', error, {
      taskId: task._id
    });
  }
});

/**
 * Analytics Events
 */
taskEvents.on('analytics:task_completed', async (data) => {
  try {
    // Store analytics data for reporting
    const analyticsKey = `analytics:task_completion:${new Date().toISOString().split('T')[0]}`;
    const analytics = await cache.get(analyticsKey) || [];
    
    analytics.push({
      ...data,
      timestamp: new Date()
    });
    
    await cache.set(analyticsKey, analytics, 7 * 24 * 60 * 60); // 7 days

    logger.info('Task completion analytics recorded', data);

  } catch (error) {
    logger.error('Error recording task analytics', error);
  }
});

/**
 * Clear task-related caches
 */
const clearTaskCaches = async (task, userId) => {
  try {
    const cacheKeys = [
      `overdue_tasks:${userId}`,
      `task_stats:${userId}`,
      `user_tasks:${userId}`,
      `tasks:*` // Clear all task list caches
    ];

    for (const key of cacheKeys) {
      if (key.includes('*')) {
        await cache.clearPattern(key);
      } else {
        await cache.del(key);
      }
    }

  } catch (error) {
    logger.error('Error clearing task caches', error);
  }
};

/**
 * Initialize task event listeners
 */
const initializeTaskEvents = () => {
  logger.info('✅ Task events initialized');
  
  // Set max listeners to prevent memory leaks
  taskEvents.setMaxListeners(50);
  
  return taskEvents;
};

module.exports = {
  taskEvents,
  initializeTaskEvents
};