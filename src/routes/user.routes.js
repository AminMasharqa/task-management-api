/**
 * User Routes
 * User management, profiles, and user-related operations
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const userController = require('../controllers/user.controller');
const authMiddleware = require('../middleware/auth.middleware');
const validationMiddleware = require('../middleware/validation.middleware');
const config = require('../config');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Configure multer for file uploads
 */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(config.upload.uploadPath, 'avatars');
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `avatar-${req.user.id}-${uniqueSuffix}${ext}`);
  }
});

const avatarUpload = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB limit for avatars
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Allow only image files
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.'), false);
    }
  }
});

/**
 * @route   GET /api/v1/users
 * @desc    Get all users with pagination and filtering
 * @access  Private (Admin only)
 */
router.get(
  '/',
  authMiddleware.requireRole(['admin']),
  validationMiddleware.validateUserQuery(),
  userController.getUsers
);

/**
 * @route   GET /api/v1/users/search
 * @desc    Search users by name, email, or username
 * @access  Private
 */
router.get(
  '/search',
  validationMiddleware.validateUserSearch(),
  userController.searchUsers
);

/**
 * @route   GET /api/v1/users/stats
 * @desc    Get user statistics (admin only)
 * @access  Private (Admin only)
 */
router.get(
  '/stats',
  authMiddleware.requireRole(['admin']),
  userController.getUserStats
);

/**
 * @route   GET /api/v1/users/:id
 * @desc    Get user by ID
 * @access  Private
 */
router.get(
  '/:id',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnershipOrRole(['admin', 'manager']),
  userController.getUserById
);

/**
 * @route   PUT /api/v1/users/:id
 * @desc    Update user profile
 * @access  Private (Owner or Admin)
 */
router.put(
  '/:id',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnershipOrRole(['admin']),
  validationMiddleware.validateUpdateUser(),
  userController.updateUser
);

/**
 * @route   DELETE /api/v1/users/:id
 * @desc    Delete user account
 * @access  Private (Owner or Admin)
 */
router.delete(
  '/:id',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnershipOrRole(['admin']),
  userController.deleteUser
);

/**
 * @route   POST /api/v1/users/:id/avatar
 * @desc    Upload user avatar
 * @access  Private (Owner only)
 */
router.post(
  '/:id/avatar',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnership(),
  avatarUpload.single('avatar'),
  userController.uploadAvatar
);

/**
 * @route   DELETE /api/v1/users/:id/avatar
 * @desc    Delete user avatar
 * @access  Private (Owner only)
 */
router.delete(
  '/:id/avatar',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnership(),
  userController.deleteAvatar
);

/**
 * @route   GET /api/v1/users/:id/tasks
 * @desc    Get user's tasks
 * @access  Private (Owner or Admin)
 */
router.get(
  '/:id/tasks',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnershipOrRole(['admin', 'manager']),
  validationMiddleware.validateTaskQuery(),
  userController.getUserTasks
);

/**
 * @route   GET /api/v1/users/:id/activity
 * @desc    Get user's activity log
 * @access  Private (Owner or Admin)
 */
router.get(
  '/:id/activity',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnershipOrRole(['admin']),
  validationMiddleware.validateActivityQuery(),
  userController.getUserActivity
);

/**
 * @route   PUT /api/v1/users/:id/status
 * @desc    Update user status (active/inactive)
 * @access  Private (Admin only)
 */
router.put(
  '/:id/status',
  validationMiddleware.validateUserId(),
  authMiddleware.requireRole(['admin']),
  validationMiddleware.validateUserStatus(),
  userController.updateUserStatus
);

/**
 * @route   PUT /api/v1/users/:id/role
 * @desc    Update user role
 * @access  Private (Admin only)
 */
router.put(
  '/:id/role',
  validationMiddleware.validateUserId(),
  authMiddleware.requireRole(['admin']),
  validationMiddleware.validateUserRole(),
  userController.updateUserRole
);

/**
 * @route   POST /api/v1/users/:id/follow
 * @desc    Follow a user
 * @access  Private
 */
router.post(
  '/:id/follow',
  validationMiddleware.validateUserId(),
  userController.followUser
);

/**
 * @route   DELETE /api/v1/users/:id/follow
 * @desc    Unfollow a user
 * @access  Private
 */
router.delete(
  '/:id/follow',
  validationMiddleware.validateUserId(),
  userController.unfollowUser
);

/**
 * @route   GET /api/v1/users/:id/followers
 * @desc    Get user's followers
 * @access  Private
 */
router.get(
  '/:id/followers',
  validationMiddleware.validateUserId(),
  validationMiddleware.validateFollowQuery(),
  userController.getUserFollowers
);

/**
 * @route   GET /api/v1/users/:id/following
 * @desc    Get users that this user is following
 * @access  Private
 */
router.get(
  '/:id/following',
  validationMiddleware.validateUserId(),
  validationMiddleware.validateFollowQuery(),
  userController.getUserFollowing
);

/**
 * @route   GET /api/v1/users/:id/preferences
 * @desc    Get user preferences
 * @access  Private (Owner only)
 */
router.get(
  '/:id/preferences',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnership(),
  userController.getUserPreferences
);

/**
 * @route   PUT /api/v1/users/:id/preferences
 * @desc    Update user preferences
 * @access  Private (Owner only)
 */
router.put(
  '/:id/preferences',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnership(),
  validationMiddleware.validateUserPreferences(),
  userController.updateUserPreferences
);

/**
 * @route   GET /api/v1/users/:id/notifications
 * @desc    Get user notifications
 * @access  Private (Owner only)
 */
router.get(
  '/:id/notifications',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnership(),
  validationMiddleware.validateNotificationQuery(),
  userController.getUserNotifications
);

/**
 * @route   PUT /api/v1/users/:id/notifications/:notificationId/read
 * @desc    Mark notification as read
 * @access  Private (Owner only)
 */
router.put(
  '/:id/notifications/:notificationId/read',
  validationMiddleware.validateUserId(),
  validationMiddleware.validateNotificationId(),
  authMiddleware.requireOwnership(),
  userController.markNotificationRead
);

/**
 * @route   DELETE /api/v1/users/:id/notifications/:notificationId
 * @desc    Delete notification
 * @access  Private (Owner only)
 */
router.delete(
  '/:id/notifications/:notificationId',
  validationMiddleware.validateUserId(),
  validationMiddleware.validateNotificationId(),
  authMiddleware.requireOwnership(),
  userController.deleteNotification
);

/**
 * @route   POST /api/v1/users/:id/export
 * @desc    Export user data (GDPR compliance)
 * @access  Private (Owner only)
 */
router.post(
  '/:id/export',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnership(),
  userController.exportUserData
);

/**
 * @route   POST /api/v1/users/:id/deactivate
 * @desc    Deactivate user account (soft delete)
 * @access  Private (Owner only)
 */
router.post(
  '/:id/deactivate',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnership(),
  validationMiddleware.validateDeactivateAccount(),
  userController.deactivateAccount
);

/**
 * @route   POST /api/v1/users/:id/reactivate
 * @desc    Reactivate user account
 * @access  Private (Admin only)
 */
router.post(
  '/:id/reactivate',
  validationMiddleware.validateUserId(),
  authMiddleware.requireRole(['admin']),
  userController.reactivateAccount
);

/**
 * Team Management Routes
 */

/**
 * @route   GET /api/v1/users/:id/teams
 * @desc    Get user's teams
 * @access  Private (Owner or Admin)
 */
router.get(
  '/:id/teams',
  validationMiddleware.validateUserId(),
  authMiddleware.requireOwnershipOrRole(['admin', 'manager']),
  userController.getUserTeams
);

/**
 * @route   POST /api/v1/users/:id/teams/:teamId/join
 * @desc    Join a team
 * @access  Private
 */
router.post(
  '/:id/teams/:teamId/join',
  validationMiddleware.validateUserId(),
  validationMiddleware.validateTeamId(),
  authMiddleware.requireOwnership(),
  userController.joinTeam
);

/**
 * @route   DELETE /api/v1/users/:id/teams/:teamId/leave
 * @desc    Leave a team
 * @access  Private (Owner only)
 */
router.delete(
  '/:id/teams/:teamId/leave',
  validationMiddleware.validateUserId(),
  validationMiddleware.validateTeamId(),
  authMiddleware.requireOwnership(),
  userController.leaveTeam
);

/**
 * Bulk Operations (Admin only)
 */

/**
 * @route   POST /api/v1/users/bulk/invite
 * @desc    Bulk invite users
 * @access  Private (Admin only)
 */
router.post(
  '/bulk/invite',
  authMiddleware.requireRole(['admin']),
  validationMiddleware.validateBulkInvite(),
  userController.bulkInviteUsers
);

/**
 * @route   PUT /api/v1/users/bulk/update
 * @desc    Bulk update users
 * @access  Private (Admin only)
 */
router.put(
  '/bulk/update',
  authMiddleware.requireRole(['admin']),
  validationMiddleware.validateBulkUpdate(),
  userController.bulkUpdateUsers
);

/**
 * @route   DELETE /api/v1/users/bulk/delete
 * @desc    Bulk delete users
 * @access  Private (Admin only)
 */
router.delete(
  '/bulk/delete',
  authMiddleware.requireRole(['admin']),
  validationMiddleware.validateBulkDelete(),
  userController.bulkDeleteUsers
);

/**
 * Route documentation endpoint
 */
router.get('/', (req, res) => {
  res.json({
    name: 'User Management API',
    version: '1.0.0',
    description: 'User management and profile operations',
    endpoints: {
      profile: [
        'GET /:id - Get user profile',
        'PUT /:id - Update user profile',
        'DELETE /:id - Delete user account',
        'POST /:id/avatar - Upload avatar',
        'DELETE /:id/avatar - Delete avatar'
      ],
      management: [
        'GET / - List all users (admin)',
        'GET /search - Search users',
        'GET /stats - User statistics (admin)',
        'PUT /:id/status - Update user status (admin)',
        'PUT /:id/role - Update user role (admin)'
      ],
      social: [
        'POST /:id/follow - Follow user',
        'DELETE /:id/follow - Unfollow user',
        'GET /:id/followers - Get followers',
        'GET /:id/following - Get following'
      ],
      data: [
        'GET /:id/tasks - Get user tasks',
        'GET /:id/activity - Get activity log',
        'GET /:id/notifications - Get notifications',
        'POST /:id/export - Export user data (GDPR)'
      ],
      teams: [
        'GET /:id/teams - Get user teams',
        'POST /:id/teams/:teamId/join - Join team',
        'DELETE /:id/teams/:teamId/leave - Leave team'
      ],
      bulk: [
        'POST /bulk/invite - Bulk invite (admin)',
        'PUT /bulk/update - Bulk update (admin)',
        'DELETE /bulk/delete - Bulk delete (admin)'
      ]
    },
    features: {
      fileUpload: 'Avatar image upload support',
      roleBasedAccess: 'Owner/Admin permission system',
      socialFeatures: 'Follow/unfollow functionality',
      dataExport: 'GDPR compliance data export',
      bulkOperations: 'Admin bulk management tools',
      notifications: 'User notification system'
    }
  });
});

/**
 * Error handler for multer file upload errors
 */
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    logger.error('File upload error', error, {
      userId: req.user?.id,
      file: req.file?.originalname
    });

    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File size too large. Maximum size is 2MB.',
        error: 'FILE_TOO_LARGE'
      });
    }

    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Too many files. Only one file allowed.',
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
      error: 'INVALID_FILE_TYPE'
    });
  }

  next(error);
});

module.exports = router;