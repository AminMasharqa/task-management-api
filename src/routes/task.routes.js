/**
 * Task Routes
 * Task management, comments, attachments, and collaboration features
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const taskController = require('../controllers/task.controller');
const authMiddleware = require('../middleware/auth.middleware');
const validationMiddleware = require('../middleware/validation.middleware');
const config = require('../config');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Configure multer for task attachments
 */
const attachmentStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(config.upload.uploadPath, 'tasks', req.params.id || 'temp');
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const baseName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9]/g, '-');
    cb(null, `${baseName}-${uniqueSuffix}${ext}`);
  }
});

const attachmentUpload = multer({
  storage: attachmentStorage,
  limits: {
    fileSize: config.upload.maxFileSize, // 5MB default
    files: 5 // Maximum 5 files per upload
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = config.upload.allowedTypes;
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Allowed types: ${allowedTypes.join(', ')}`), false);
    }
  }
});

/**
 * Task CRUD Operations
 */

/**
 * @route   GET /api/v1/tasks
 * @desc    Get tasks with filtering, sorting, and pagination
 * @access  Private
 */
router.get(
  '/',
  validationMiddleware.validateTaskQuery(),
  taskController.getTasks
);

/**
 * @route   POST /api/v1/tasks
 * @desc    Create a new task
 * @access  Private
 */
router.post(
  '/',
  validationMiddleware.validateCreateTask(),
  taskController.createTask
);

/**
 * @route   GET /api/v1/tasks/my
 * @desc    Get current user's tasks
 * @access  Private
 */
router.get(
  '/my',
  validationMiddleware.validateTaskQuery(),
  taskController.getMyTasks
);

/**
 * @route   GET /api/v1/tasks/assigned-to-me
 * @desc    Get tasks assigned to current user
 * @access  Private
 */
router.get(
  '/assigned-to-me',
  validationMiddleware.validateTaskQuery(),
  taskController.getTasksAssignedToMe
);

/**
 * @route   GET /api/v1/tasks/stats
 * @desc    Get task statistics
 * @access  Private
 */
router.get(
  '/stats',
  validationMiddleware.validateStatsQuery(),
  taskController.getTaskStats
);

/**
 * @route   GET /api/v1/tasks/search
 * @desc    Search tasks by title, description, or tags
 * @access  Private
 */
router.get(
  '/search',
  validationMiddleware.validateTaskSearch(),
  taskController.searchTasks
);

/**
 * @route   GET /api/v1/tasks/:id
 * @desc    Get task by ID
 * @access  Private
 */
router.get(
  '/:id',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(),
  taskController.getTaskById
);

/**
 * @route   PUT /api/v1/tasks/:id
 * @desc    Update task
 * @access  Private (Owner, Assignee, or Admin)
 */
router.put(
  '/:id',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'assignee', 'admin']),
  validationMiddleware.validateUpdateTask(),
  taskController.updateTask
);

/**
 * @route   DELETE /api/v1/tasks/:id
 * @desc    Delete task
 * @access  Private (Owner or Admin)
 */
router.delete(
  '/:id',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'admin']),
  taskController.deleteTask
);

/**
 * Task Status Operations
 */

/**
 * @route   PUT /api/v1/tasks/:id/status
 * @desc    Update task status
 * @access  Private (Owner, Assignee, or Admin)
 */
router.put(
  '/:id/status',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'assignee', 'admin']),
  validationMiddleware.validateTaskStatus(),
  taskController.updateTaskStatus
);

/**
 * @route   PUT /api/v1/tasks/:id/priority
 * @desc    Update task priority
 * @access  Private (Owner or Admin)
 */
router.put(
  '/:id/priority',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'admin']),
  validationMiddleware.validateTaskPriority(),
  taskController.updateTaskPriority
);

/**
 * @route   PUT /api/v1/tasks/:id/assign
 * @desc    Assign task to user(s)
 * @access  Private (Owner or Admin)
 */
router.put(
  '/:id/assign',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'admin']),
  validationMiddleware.validateTaskAssignment(),
  taskController.assignTask
);

/**
 * @route   DELETE /api/v1/tasks/:id/assign/:userId
 * @desc    Unassign user from task
 * @access  Private (Owner or Admin)
 */
router.delete(
  '/:id/assign/:userId',
  validationMiddleware.validateTaskId(),
  validationMiddleware.validateUserId('userId'),
  authMiddleware.requireTaskAccess(['owner', 'admin']),
  taskController.unassignTask
);

/**
 * Task Collaboration Features
 */

/**
 * @route   GET /api/v1/tasks/:id/comments
 * @desc    Get task comments
 * @access  Private
 */
router.get(
  '/:id/comments',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(),
  validationMiddleware.validateCommentQuery(),
  taskController.getTaskComments
);

/**
 * @route   POST /api/v1/tasks/:id/comments
 * @desc    Add comment to task
 * @access  Private
 */
router.post(
  '/:id/comments',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(),
  validationMiddleware.validateCreateComment(),
  taskController.addTaskComment
);

/**
 * @route   PUT /api/v1/tasks/:id/comments/:commentId
 * @desc    Update task comment
 * @access  Private (Comment owner or Admin)
 */
router.put(
  '/:id/comments/:commentId',
  validationMiddleware.validateTaskId(),
  validationMiddleware.validateCommentId(),
  authMiddleware.requireTaskAccess(),
  authMiddleware.requireCommentOwnership(),
  validationMiddleware.validateUpdateComment(),
  taskController.updateTaskComment
);

/**
 * @route   DELETE /api/v1/tasks/:id/comments/:commentId
 * @desc    Delete task comment
 * @access  Private (Comment owner or Admin)
 */
router.delete(
  '/:id/comments/:commentId',
  validationMiddleware.validateTaskId(),
  validationMiddleware.validateCommentId(),
  authMiddleware.requireTaskAccess(),
  authMiddleware.requireCommentOwnership(),
  taskController.deleteTaskComment
);

/**
 * Task Attachments
 */

/**
 * @route   GET /api/v1/tasks/:id/attachments
 * @desc    Get task attachments
 * @access  Private
 */
router.get(
  '/:id/attachments',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(),
  taskController.getTaskAttachments
);

/**
 * @route   POST /api/v1/tasks/:id/attachments
 * @desc    Upload task attachments
 * @access  Private
 */
router.post(
  '/:id/attachments',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(),
  attachmentUpload.array('attachments', 5),
  taskController.uploadTaskAttachments
);

/**
 * @route   DELETE /api/v1/tasks/:id/attachments/:attachmentId
 * @desc    Delete task attachment
 * @access  Private (Uploader or Admin)
 */
router.delete(
  '/:id/attachments/:attachmentId',
  validationMiddleware.validateTaskId(),
  validationMiddleware.validateAttachmentId(),
  authMiddleware.requireTaskAccess(),
  authMiddleware.requireAttachmentOwnership(),
  taskController.deleteTaskAttachment
);

/**
 * @route   GET /api/v1/tasks/:id/attachments/:attachmentId/download
 * @desc    Download task attachment
 * @access  Private
 */
router.get(
  '/:id/attachments/:attachmentId/download',
  validationMiddleware.validateTaskId(),
  validationMiddleware.validateAttachmentId(),
  authMiddleware.requireTaskAccess(),
  taskController.downloadTaskAttachment
);

/**
 * Task Organization
 */

/**
 * @route   PUT /api/v1/tasks/:id/tags
 * @desc    Update task tags
 * @access  Private (Owner or Admin)
 */
router.put(
  '/:id/tags',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'admin']),
  validationMiddleware.validateTaskTags(),
  taskController.updateTaskTags
);

/**
 * @route   PUT /api/v1/tasks/:id/due-date
 * @desc    Update task due date
 * @access  Private (Owner or Admin)
 */
router.put(
  '/:id/due-date',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'admin']),
  validationMiddleware.validateTaskDueDate(),
  taskController.updateTaskDueDate
);

/**
 * @route   POST /api/v1/tasks/:id/duplicate
 * @desc    Duplicate task
 * @access  Private
 */
router.post(
  '/:id/duplicate',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(),
  validationMiddleware.validateDuplicateTask(),
  taskController.duplicateTask
);

/**
 * Task Templates
 */

/**
 * @route   GET /api/v1/tasks/templates
 * @desc    Get task templates
 * @access  Private
 */
router.get(
  '/templates',
  validationMiddleware.validateTemplateQuery(),
  taskController.getTaskTemplates
);

/**
 * @route   POST /api/v1/tasks/templates
 * @desc    Create task template
 * @access  Private
 */
router.post(
  '/templates',
  validationMiddleware.validateCreateTemplate(),
  taskController.createTaskTemplate
);

/**
 * @route   POST /api/v1/tasks/from-template/:templateId
 * @desc    Create task from template
 * @access  Private
 */
router.post(
  '/from-template/:templateId',
  validationMiddleware.validateTemplateId(),
  validationMiddleware.validateCreateFromTemplate(),
  taskController.createTaskFromTemplate
);

/**
 * Bulk Operations
 */

/**
 * @route   PUT /api/v1/tasks/bulk/status
 * @desc    Bulk update task status
 * @access  Private
 */
router.put(
  '/bulk/status',
  validationMiddleware.validateBulkStatusUpdate(),
  taskController.bulkUpdateTaskStatus
);

/**
 * @route   PUT /api/v1/tasks/bulk/assign
 * @desc    Bulk assign tasks
 * @access  Private
 */
router.put(
  '/bulk/assign',
  validationMiddleware.validateBulkAssign(),
  taskController.bulkAssignTasks
);

/**
 * @route   DELETE /api/v1/tasks/bulk/delete
 * @desc    Bulk delete tasks
 * @access  Private
 */
router.delete(
  '/bulk/delete',
  validationMiddleware.validateBulkDelete(),
  taskController.bulkDeleteTasks
);

/**
 * Task Analytics
 */

/**
 * @route   GET /api/v1/tasks/analytics/completion-rate
 * @desc    Get task completion analytics
 * @access  Private
 */
router.get(
  '/analytics/completion-rate',
  validationMiddleware.validateAnalyticsQuery(),
  taskController.getCompletionAnalytics
);

/**
 * @route   GET /api/v1/tasks/analytics/time-tracking
 * @desc    Get time tracking analytics
 * @access  Private
 */
router.get(
  '/analytics/time-tracking',
  validationMiddleware.validateAnalyticsQuery(),
  taskController.getTimeTrackingAnalytics
);

/**
 * Time Tracking
 */

/**
 * @route   POST /api/v1/tasks/:id/time/start
 * @desc    Start time tracking for task
 * @access  Private
 */
router.post(
  '/:id/time/start',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'assignee']),
  taskController.startTimeTracking
);

/**
 * @route   POST /api/v1/tasks/:id/time/stop
 * @desc    Stop time tracking for task
 * @access  Private
 */
router.post(
  '/:id/time/stop',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(['owner', 'assignee']),
  taskController.stopTimeTracking
);

/**
 * @route   GET /api/v1/tasks/:id/time
 * @desc    Get task time entries
 * @access  Private
 */
router.get(
  '/:id/time',
  validationMiddleware.validateTaskId(),
  authMiddleware.requireTaskAccess(),
  taskController.getTaskTimeEntries
);

/**
 * Route documentation endpoint
 */
router.get('/', (req, res) => {
  res.json({
    name: 'Task Management API',
    version: '1.0.0',
    description: 'Comprehensive task management with collaboration features',
    endpoints: {
      crud: [
        'GET / - List tasks with filtering',
        'POST / - Create new task',
        'GET /:id - Get task details',
        'PUT /:id - Update task',
        'DELETE /:id - Delete task'
      ],
      status: [
        'PUT /:id/status - Update status',
        'PUT /:id/priority - Update priority',
        'PUT /:id/assign - Assign users',
        'DELETE /:id/assign/:userId - Unassign user'
      ],
      collaboration: [
        'GET /:id/comments - Get comments',
        'POST /:id/comments - Add comment',
        'PUT /:id/comments/:commentId - Update comment',
        'DELETE /:id/comments/:commentId - Delete comment'
      ],
      attachments: [
        'GET /:id/attachments - List attachments',
        'POST /:id/attachments - Upload files',
        'DELETE /:id/attachments/:attachmentId - Delete file',
        'GET /:id/attachments/:attachmentId/download - Download file'
      ],
      organization: [
        'PUT /:id/tags - Update tags',
        'PUT /:id/due-date - Set due date',
        'POST /:id/duplicate - Duplicate task'
      ],
      templates: [
        'GET /templates - List templates',
        'POST /templates - Create template',
        'POST /from-template/:templateId - Create from template'
      ],
      bulk: [
        'PUT /bulk/status - Bulk status update',
        'PUT /bulk/assign - Bulk assignment',
        'DELETE /bulk/delete - Bulk delete'
      ],
      tracking: [
        'POST /:id/time/start - Start timer',
        'POST /:id/time/stop - Stop timer',
        'GET /:id/time - Get time entries'
      ],
      analytics: [
        'GET /analytics/completion-rate - Completion stats',
        'GET /analytics/time-tracking - Time stats'
      ]
    },
    features: {
      fileUpload: 'Task attachment support (5MB max, 5 files)',
      realtime: 'WebSocket notifications for task updates',
      collaboration: 'Comments and assignment system',
      timeTracking: 'Built-in time tracking for tasks',
      templates: 'Reusable task templates',
      bulkOperations: 'Efficient bulk management',
      analytics: 'Task completion and time analytics',
      search: 'Full-text search across tasks'
    }
  });
});

/**
 * Error handler for multer file upload errors
 */
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    logger.error('Task attachment upload error', error, {
      userId: req.user?.id,
      taskId: req.params?.id,
      files: req.files?.map(f => f.originalname)
    });

    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: `File size too large. Maximum size is ${Math.round(config.upload.maxFileSize / 1024 / 1024)}MB.`,
        error: 'FILE_TOO_LARGE'
      });
    }

    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Too many files. Maximum 5 files per upload.',
        error: 'TOO_MANY_FILES'
      });
    }

    return res.status(400).json({
      success: false,
      message: 'File upload error',
      error: error.code
    });
  }

  if (error.message.includes('Invalid file type')) {
    return res.status(400).json({
      success: false,
      message: error.message,
      error: 'INVALID_FILE_TYPE',
      allowedTypes: config.upload.allowedTypes
    });
  }

  next(error);
});

module.exports = router;