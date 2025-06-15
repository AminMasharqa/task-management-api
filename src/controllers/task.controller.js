/**
 * Task Controller
 * Handles task management, collaboration, and productivity features
 */

const fs = require('fs').promises;
const path = require('path');
const Task = require('../models/Task');
const User = require('../models/User');
const taskService = require('../services/task.service');
const notificationService = require('../services/notification.service');
const { cache, pubsub } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * @desc    Get tasks with filtering, sorting, and pagination
 * @route   GET /api/v1/tasks
 * @access  Private
 */
const getTasks = async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 10,
      status,
      priority,
      assignedTo,
      createdBy,
      tags,
      dueBefore,
      dueAfter,
      search,
      sort = '-createdAt'
    } = req.query;

    // Build filter object
    const filter = {};
    
    // Add user access control
    if (!['admin', 'manager'].includes(req.user.role)) {
      filter.$or = [
        { createdBy: req.user.id },
        { assignedTo: req.user.id },
        { collaborators: req.user.id }
      ];
    }

    // Apply filters
    if (status) filter.status = status;
    if (priority) filter.priority = priority;
    if (assignedTo) filter.assignedTo = assignedTo;
    if (createdBy) filter.createdBy = createdBy;
    if (tags) filter.tags = { $in: tags.split(',') };
    
    // Date filters
    if (dueBefore || dueAfter) {
      filter.dueDate = {};
      if (dueBefore) filter.dueDate.$lte = new Date(dueBefore);
      if (dueAfter) filter.dueDate.$gte = new Date(dueAfter);
    }

    // Search functionality
    if (search) {
      filter.$and = filter.$and || [];
      filter.$and.push({
        $or: [
          { title: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } },
          { tags: { $regex: search, $options: 'i' } }
        ]
      });
    }

    // Calculate pagination
    const skip = (page - 1) * parseInt(limit);
    const limitNum = parseInt(limit);

    // Get tasks and total count
    const [tasks, total] = await Promise.all([
      Task.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(limitNum)
        .populate('createdBy', 'firstName lastName username profile.avatar')
        .populate('assignedTo', 'firstName lastName username profile.avatar')
        .populate('collaborators', 'firstName lastName username profile.avatar')
        .lean(),
      Task.countDocuments(filter)
    ]);

    // Calculate pagination info
    const totalPages = Math.ceil(total / limitNum);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    logger.info('Tasks retrieved', {
      userId: req.user.id,
      filters: Object.keys(filter),
      total,
      page
    });

    res.status(200).json({
      success: true,
      data: {
        tasks,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalTasks: total,
          hasNextPage,
          hasPrevPage,
          limit: limitNum
        }
      }
    });

  } catch (error) {
    logger.error('Get tasks error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Create a new task
 * @route   POST /api/v1/tasks
 * @access  Private
 */
const createTask = async (req, res, next) => {
  try {
    const taskData = {
      ...req.body,
      createdBy: req.user.id
    };

    // Create task
    const task = new Task(taskData);
    await task.save();

    // Populate task for response
    await task.populate([
      { path: 'createdBy', select: 'firstName lastName username' },
      { path: 'assignedTo', select: 'firstName lastName username' }
    ]);

    // Send notifications to assigned users
    if (task.assignedTo && task.assignedTo.length > 0) {
      try {
        await notificationService.notifyTaskAssignment(task, req.user);
      } catch (notificationError) {
        logger.error('Failed to send task assignment notifications', notificationError);
      }
    }

    // Publish real-time update
    await pubsub.publish('task:created', {
      task: task.toObject(),
      createdBy: req.user
    });

    // Clear relevant caches
    await cache.clearPattern('tasks:*');

    logger.business('Task created', {
      taskId: task._id,
      title: task.title,
      createdBy: req.user.id,
      assignedTo: task.assignedTo?.map(u => u._id) || []
    });

    res.status(201).json({
      success: true,
      message: 'Task created successfully',
      data: { task }
    });

  } catch (error) {
    logger.error('Create task error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get current user's tasks
 * @route   GET /api/v1/tasks/my
 * @access  Private
 */
const getMyTasks = async (req, res, next) => {
  try {
    const { status, priority, sort = '-createdAt' } = req.query;

    // Build filter for user's tasks
    const filter = { createdBy: req.user.id };
    if (status) filter.status = status;
    if (priority) filter.priority = priority;

    const tasks = await Task.find(filter)
      .sort(sort)
      .populate('assignedTo', 'firstName lastName username profile.avatar')
      .lean();

    // Group tasks by status for dashboard view
    const tasksByStatus = {
      todo: tasks.filter(t => t.status === 'todo'),
      inProgress: tasks.filter(t => t.status === 'in-progress'),
      completed: tasks.filter(t => t.status === 'completed'),
      cancelled: tasks.filter(t => t.status === 'cancelled')
    };

    res.status(200).json({
      success: true,
      data: {
        tasks,
        tasksByStatus,
        summary: {
          total: tasks.length,
          completed: tasksByStatus.completed.length,
          inProgress: tasksByStatus.inProgress.length,
          todo: tasksByStatus.todo.length
        }
      }
    });

  } catch (error) {
    logger.error('Get my tasks error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get tasks assigned to current user
 * @route   GET /api/v1/tasks/assigned-to-me
 * @access  Private
 */
const getTasksAssignedToMe = async (req, res, next) => {
  try {
    const { status, priority, sort = '-updatedAt' } = req.query;

    // Build filter for assigned tasks
    const filter = { assignedTo: req.user.id };
    if (status) filter.status = status;
    if (priority) filter.priority = priority;

    const tasks = await Task.find(filter)
      .sort(sort)
      .populate('createdBy', 'firstName lastName username profile.avatar')
      .populate('assignedTo', 'firstName lastName username profile.avatar')
      .lean();

    // Separate overdue tasks
    const now = new Date();
    const overdueTasks = tasks.filter(t => 
      t.dueDate && new Date(t.dueDate) < now && !['completed', 'cancelled'].includes(t.status)
    );

    res.status(200).json({
      success: true,
      data: {
        tasks,
        overdueTasks,
        summary: {
          total: tasks.length,
          overdue: overdueTasks.length,
          pending: tasks.filter(t => ['todo', 'in-progress'].includes(t.status)).length
        }
      }
    });

  } catch (error) {
    logger.error('Get assigned tasks error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get task statistics
 * @route   GET /api/v1/tasks/stats
 * @access  Private
 */
const getTaskStats = async (req, res, next) => {
  try {
    const { timeframe = '30d' } = req.query;
    
    // Calculate date range
    const days = parseInt(timeframe.replace('d', ''));
    const dateFrom = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    // Build user filter
    const userFilter = ['admin', 'manager'].includes(req.user.role) 
      ? {} 
      : { 
          $or: [
            { createdBy: req.user.id },
            { assignedTo: req.user.id }
          ]
        };

    // Get task statistics
    const [
      totalTasks,
      completedTasks,
      recentTasks,
      statusDistribution,
      priorityDistribution,
      completionTrend
    ] = await Promise.all([
      Task.countDocuments(userFilter),
      Task.countDocuments({ ...userFilter, status: 'completed' }),
      Task.countDocuments({ 
        ...userFilter, 
        createdAt: { $gte: dateFrom } 
      }),
      Task.aggregate([
        { $match: userFilter },
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]),
      Task.aggregate([
        { $match: userFilter },
        { $group: { _id: '$priority', count: { $sum: 1 } } }
      ]),
      Task.aggregate([
        {
          $match: {
            ...userFilter,
            completedAt: { $gte: dateFrom }
          }
        },
        {
          $group: {
            _id: {
              date: { $dateToString: { format: "%Y-%m-%d", date: "$completedAt" } }
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { '_id.date': 1 } }
      ])
    ]);

    const stats = {
      overview: {
        totalTasks,
        completedTasks,
        recentTasks,
        completionRate: totalTasks > 0 ? ((completedTasks / totalTasks) * 100).toFixed(1) : 0
      },
      distribution: {
        status: statusDistribution,
        priority: priorityDistribution
      },
      trends: {
        completion: completionTrend
      }
    };

    res.status(200).json({
      success: true,
      data: { stats }
    });

  } catch (error) {
    logger.error('Get task stats error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Search tasks
 * @route   GET /api/v1/tasks/search
 * @access  Private
 */
const searchTasks = async (req, res, next) => {
  try {
    const { q: query, limit = 20 } = req.query;

    if (!query || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        message: 'Search query must be at least 2 characters long'
      });
    }

    // Build search filter
    const searchFilter = {
      $and: [
        // User access control
        {
          $or: [
            { createdBy: req.user.id },
            { assignedTo: req.user.id },
            { collaborators: req.user.id }
          ]
        },
        // Search criteria
        {
          $or: [
            { title: { $regex: query, $options: 'i' } },
            { description: { $regex: query, $options: 'i' } },
            { tags: { $regex: query, $options: 'i' } }
          ]
        }
      ]
    };

    const tasks = await Task.find(searchFilter)
      .limit(parseInt(limit))
      .populate('createdBy', 'firstName lastName username')
      .populate('assignedTo', 'firstName lastName username')
      .select('title description status priority dueDate tags createdAt')
      .lean();

    logger.info('Task search performed', {
      query,
      resultsCount: tasks.length,
      searchedBy: req.user.id
    });

    res.status(200).json({
      success: true,
      data: { tasks }
    });

  } catch (error) {
    logger.error('Search tasks error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get task by ID
 * @route   GET /api/v1/tasks/:id
 * @access  Private
 */
const getTaskById = async (req, res, next) => {
  try {
    const { id } = req.params;

    const task = await Task.findById(id)
      .populate('createdBy', 'firstName lastName username profile.avatar')
      .populate('assignedTo', 'firstName lastName username profile.avatar')
      .populate('collaborators', 'firstName lastName username profile.avatar')
      .populate({
        path: 'comments.author',
        select: 'firstName lastName username profile.avatar'
      })
      .lean();

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Get time tracking entries if user has access
    const hasAccess = task.createdBy._id.toString() === req.user.id ||
                     task.assignedTo.some(u => u._id.toString() === req.user.id) ||
                     ['admin', 'manager'].includes(req.user.role);

    if (hasAccess && task.timeEntries) {
      task.totalTimeSpent = task.timeEntries.reduce((total, entry) => {
        return total + (entry.duration || 0);
      }, 0);
    }

    logger.info('Task retrieved', {
      taskId: id,
      requestedBy: req.user.id,
      hasAccess
    });

    res.status(200).json({
      success: true,
      data: { task }
    });

  } catch (error) {
    logger.error('Get task by ID error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Update task
 * @route   PUT /api/v1/tasks/:id
 * @access  Private (Owner, Assignee, or Admin)
 */
const updateTask = async (req, res, next) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    // Get original task for comparison
    const originalTask = await Task.findById(id);
    if (!originalTask) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Track changes for notifications
    const changes = {};
    Object.keys(updateData).forEach(key => {
      if (JSON.stringify(originalTask[key]) !== JSON.stringify(updateData[key])) {
        changes[key] = {
          from: originalTask[key],
          to: updateData[key]
        };
      }
    });

    // Update task
    const task = await Task.findByIdAndUpdate(
      id,
      { 
        $set: {
          ...updateData,
          updatedBy: req.user.id,
          updatedAt: new Date()
        }
      },
      { new: true, runValidators: true }
    ).populate([
      { path: 'createdBy', select: 'firstName lastName username' },
      { path: 'assignedTo', select: 'firstName lastName username' }
    ]);

    // Send notifications for significant changes
    if (Object.keys(changes).length > 0) {
      try {
        await notificationService.notifyTaskUpdate(task, req.user, changes);
      } catch (notificationError) {
        logger.error('Failed to send task update notifications', notificationError);
      }
    }

    // Publish real-time update
    await pubsub.publish('task:updated', {
      task: task.toObject(),
      changes,
      updatedBy: req.user
    });

    // Clear caches
    await cache.clearPattern('tasks:*');

    logger.business('Task updated', {
      taskId: id,
      updatedBy: req.user.id,
      changes: Object.keys(changes)
    });

    res.status(200).json({
      success: true,
      message: 'Task updated successfully',
      data: { task, changes }
    });

  } catch (error) {
    logger.error('Update task error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Delete task
 * @route   DELETE /api/v1/tasks/:id
 * @access  Private (Owner or Admin)
 */
const deleteTask = async (req, res, next) => {
  try {
    const { id } = req.params;

    const task = await Task.findById(id);
    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Delete task attachments
    if (task.attachments && task.attachments.length > 0) {
      for (const attachment of task.attachments) {
        try {
          const filePath = path.join(config.upload.uploadPath, 'tasks', id, attachment.filename);
          await fs.unlink(filePath);
        } catch (unlinkError) {
          logger.warn('Failed to delete task attachment', unlinkError);
        }
      }
    }

    // Soft delete: mark as deleted instead of removing
    await Task.findByIdAndUpdate(id, {
      isDeleted: true,
      deletedAt: new Date(),
      deletedBy: req.user.id
    });

    // Notify users involved in the task
    try {
      await notificationService.notifyTaskDeletion(task, req.user);
    } catch (notificationError) {
      logger.error('Failed to send task deletion notifications', notificationError);
    }

    // Publish real-time update
    await pubsub.publish('task:deleted', {
      taskId: id,
      deletedBy: req.user
    });

    // Clear caches
    await cache.clearPattern('tasks:*');

    logger.business('Task deleted', {
      taskId: id,
      title: task.title,
      deletedBy: req.user.id
    });

    res.status(200).json({
      success: true,
      message: 'Task deleted successfully'
    });

  } catch (error) {
    logger.error('Delete task error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Update task status
 * @route   PUT /api/v1/tasks/:id/status
 * @access  Private (Owner, Assignee, or Admin)
 */
const updateTaskStatus = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const updateData = { 
      status,
      updatedBy: req.user.id 
    };

    // Set completion date if marking as completed
    if (status === 'completed') {
      updateData.completedAt = new Date();
      updateData.completedBy = req.user.id;
    }

    const task = await Task.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    ).populate('assignedTo createdBy', 'firstName lastName username');

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Send status change notifications
    try {
      await notificationService.notifyStatusChange(task, req.user, status);
    } catch (notificationError) {
      logger.error('Failed to send status change notifications', notificationError);
    }

    // Publish real-time update
    await pubsub.publish('task:status_changed', {
      taskId: id,
      status,
      changedBy: req.user
    });

    logger.business('Task status updated', {
      taskId: id,
      newStatus: status,
      updatedBy: req.user.id
    });

    res.status(200).json({
      success: true,
      message: 'Task status updated successfully',
      data: { task }
    });

  } catch (error) {
    logger.error('Update task status error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Update task priority
 * @route   PUT /api/v1/tasks/:id/priority
 * @access  Private (Owner or Admin)
 */
const updateTaskPriority = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { priority } = req.body;

    const task = await Task.findByIdAndUpdate(
      id,
      { 
        priority,
        updatedBy: req.user.id 
      },
      { new: true }
    ).populate('assignedTo createdBy', 'firstName lastName username');

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Notify on high priority tasks
    if (priority === 'high' || priority === 'urgent') {
      try {
        await notificationService.notifyHighPriorityTask(task, req.user);
      } catch (notificationError) {
        logger.error('Failed to send priority change notifications', notificationError);
      }
    }

    logger.business('Task priority updated', {
      taskId: id,
      newPriority: priority,
      updatedBy: req.user.id
    });

    res.status(200).json({
      success: true,
      message: 'Task priority updated successfully',
      data: { task }
    });

  } catch (error) {
    logger.error('Update task priority error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Assign task to user(s)
 * @route   PUT /api/v1/tasks/:id/assign
 * @access  Private (Owner or Admin)
 */
const assignTask = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { userIds } = req.body;

    // Validate that users exist
    const users = await User.find({ 
      _id: { $in: userIds },
      isActive: true 
    }).select('firstName lastName username email');

    if (users.length !== userIds.length) {
      return res.status(400).json({
        success: false,
        message: 'One or more users not found or inactive'
      });
    }

    const task = await Task.findByIdAndUpdate(
      id,
      { 
        assignedTo: userIds,
        updatedBy: req.user.id 
      },
      { new: true }
    ).populate('assignedTo createdBy', 'firstName lastName username email');

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Send assignment notifications
    try {
      await notificationService.notifyTaskAssignment(task, req.user);
    } catch (notificationError) {
      logger.error('Failed to send assignment notifications', notificationError);
    }

    logger.business('Task assigned', {
      taskId: id,
      assignedTo: userIds,
      assignedBy: req.user.id
    });

    res.status(200).json({
      success: true,
      message: 'Task assigned successfully',
      data: { task }
    });

  } catch (error) {
    logger.error('Assign task error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Unassign user from task
 * @route   DELETE /api/v1/tasks/:id/assign/:userId
 * @access  Private (Owner or Admin)
 */
const unassignTask = async (req, res, next) => {
  try {
    const { id, userId } = req.params;

    const task = await Task.findByIdAndUpdate(
      id,
      { 
        $pull: { assignedTo: userId },
        updatedBy: req.user.id 
      },
      { new: true }
    ).populate('assignedTo createdBy', 'firstName lastName username');

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    logger.business('User unassigned from task', {
      taskId: id,
      unassignedUser: userId,
      unassignedBy: req.user.id
    });

    res.status(200).json({
      success: true,
      message: 'User unassigned successfully',
      data: { task }
    });

  } catch (error) {
    logger.error('Unassign task error', error, { userId: req.user?.id });
    next(error);
  }
};

// Placeholder functions for features to be implemented later
const getTaskComments = async (req, res) => {
  res.status(501).json({ success: false, message: 'Comments feature not yet implemented' });
};

const addTaskComment = async (req, res) => {
  res.status(501).json({ success: false, message: 'Add comment not yet implemented' });
};

const updateTaskComment = async (req, res) => {
  res.status(501).json({ success: false, message: 'Update comment not yet implemented' });
};

const deleteTaskComment = async (req, res) => {
  res.status(501).json({ success: false, message: 'Delete comment not yet implemented' });
};

const getTaskAttachments = async (req, res) => {
  res.status(501).json({ success: false, message: 'Attachments feature not yet implemented' });
};

const uploadTaskAttachments = async (req, res) => {
  res.status(501).json({ success: false, message: 'Upload attachments not yet implemented' });
};

const deleteTaskAttachment = async (req, res) => {
  res.status(501).json({ success: false, message: 'Delete attachment not yet implemented' });
};

const downloadTaskAttachment = async (req, res) => {
  res.status(501).json({ success: false, message: 'Download attachment not yet implemented' });
};

const updateTaskTags = async (req, res) => {
  res.status(501).json({ success: false, message: 'Update tags not yet implemented' });
};

const updateTaskDueDate = async (req, res) => {
  res.status(501).json({ success: false, message: 'Update due date not yet implemented' });
};

const duplicateTask = async (req, res) => {
  res.status(501).json({ success: false, message: 'Duplicate task not yet implemented' });
};

const getTaskTemplates = async (req, res) => {
  res.status(501).json({ success: false, message: 'Templates not yet implemented' });
};

const createTaskTemplate = async (req, res) => {
  res.status(501).json({ success: false, message: 'Create template not yet implemented' });
};

const createTaskFromTemplate = async (req, res) => {
  res.status(501).json({ success: false, message: 'Create from template not yet implemented' });
};

const bulkUpdateTaskStatus = async (req, res) => {
  res.status(501).json({ success: false, message: 'Bulk status update not yet implemented' });
};

const bulkAssignTasks = async (req, res) => {
  res.status(501).json({ success: false, message: 'Bulk assign not yet implemented' });
};

const bulkDeleteTasks = async (req, res) => {
  res.status(501).json({ success: false, message: 'Bulk delete not yet implemented' });
};

const getCompletionAnalytics = async (req, res) => {
  res.status(501).json({ success: false, message: 'Completion analytics not yet implemented' });
};

const getTimeTrackingAnalytics = async (req, res) => {
  res.status(501).json({ success: false, message: 'Time tracking analytics not yet implemented' });
};

const startTimeTracking = async (req, res) => {
  res.status(501).json({ success: false, message: 'Time tracking not yet implemented' });
};

const stopTimeTracking = async (req, res) => {
  res.status(501).json({ success: false, message: 'Stop time tracking not yet implemented' });
};

const getTaskTimeEntries = async (req, res) => {
  res.status(501).json({ success: false, message: 'Time entries not yet implemented' });
};

module.exports = {
  getTasks,
  createTask,
  getMyTasks,
  getTasksAssignedToMe,
  getTaskStats,
  searchTasks,
  getTaskById,
  updateTask,
  deleteTask,
  updateTaskStatus,
  updateTaskPriority,
  assignTask,
  unassignTask,
  getTaskComments,
  addTaskComment,
  updateTaskComment,
  deleteTaskComment,
  getTaskAttachments,
  uploadTaskAttachments,
  deleteTaskAttachment,
  downloadTaskAttachment,
  updateTaskTags,
  updateTaskDueDate,
  duplicateTask,
  getTaskTemplates,
  createTaskTemplate,
  createTaskFromTemplate,
  bulkUpdateTaskStatus,
  bulkAssignTasks,
  bulkDeleteTasks,
  getCompletionAnalytics,
  getTimeTrackingAnalytics,
  startTimeTracking,
  stopTimeTracking,
  getTaskTimeEntries
};