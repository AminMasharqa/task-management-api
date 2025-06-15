/**
 * User Controller
 * Handles user management, profiles, and user-related operations
 */

const fs = require('fs').promises;
const path = require('path');
const User = require('../models/User');
const Task = require('../models/Task');
const userService = require('../services/user.service');
const notificationService = require('../services/notification.service');
const { cache } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * @desc    Get all users with pagination and filtering
 * @route   GET /api/v1/users
 * @access  Private (Admin only)
 */
const getUsers = async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 10,
      sort = '-createdAt',
      role,
      isActive,
      emailVerified,
      search
    } = req.query;

    // Build filter object
    const filter = {};
    
    if (role) filter.role = role;
    if (isActive !== undefined) filter.isActive = isActive === 'true';
    if (emailVerified !== undefined) filter.emailVerified = emailVerified === 'true';
    
    if (search) {
      filter.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } }
      ];
    }

    // Calculate pagination
    const skip = (page - 1) * parseInt(limit);
    const limitNum = parseInt(limit);

    // Get users and total count
    const [users, total] = await Promise.all([
      User.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(limitNum)
        .select('-password')
        .lean(),
      User.countDocuments(filter)
    ]);

    // Calculate pagination info
    const totalPages = Math.ceil(total / limitNum);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    logger.info('Users retrieved', {
      requestedBy: req.user.id,
      total,
      page,
      limit,
      filters: filter
    });

    res.status(200).json({
      success: true,
      data: {
        users,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalUsers: total,
          hasNextPage,
          hasPrevPage,
          limit: limitNum
        }
      }
    });

  } catch (error) {
    logger.error('Get users error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Search users by name, email, or username
 * @route   GET /api/v1/users/search
 * @access  Private
 */
const searchUsers = async (req, res, next) => {
  try {
    const { q: query, limit = 10 } = req.query;

    if (!query || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        message: 'Search query must be at least 2 characters long'
      });
    }

    // Cache key for search results
    const cacheKey = `user_search:${query.toLowerCase()}:${limit}`;
    
    // Try to get from cache first
    const cachedResults = await cache.get(cacheKey);
    if (cachedResults) {
      return res.status(200).json({
        success: true,
        data: { users: cachedResults },
        cached: true
      });
    }

    // Search users
    const users = await User.find({
      $and: [
        { isActive: true },
        {
          $or: [
            { firstName: { $regex: query, $options: 'i' } },
            { lastName: { $regex: query, $options: 'i' } },
            { username: { $regex: query, $options: 'i' } },
            { email: { $regex: query, $options: 'i' } }
          ]
        }
      ]
    })
    .select('firstName lastName username email profile.avatar role')
    .limit(parseInt(limit))
    .lean();

    // Cache results for 5 minutes
    await cache.set(cacheKey, users, 300);

    logger.info('User search performed', {
      query,
      resultsCount: users.length,
      searchedBy: req.user.id
    });

    res.status(200).json({
      success: true,
      data: { users }
    });

  } catch (error) {
    logger.error('Search users error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get user statistics
 * @route   GET /api/v1/users/stats
 * @access  Private (Admin only)
 */
const getUserStats = async (req, res, next) => {
  try {
    // Get basic user statistics
    const [
      totalUsers,
      activeUsers,
      verifiedUsers,
      adminUsers,
      recentUsers
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true }),
      User.countDocuments({ emailVerified: true }),
      User.countDocuments({ role: 'admin' }),
      User.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
      })
    ]);

    // Get role distribution
    const roleDistribution = await User.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Get user growth over last 12 months
    const userGrowth = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);

    const stats = {
      overview: {
        totalUsers,
        activeUsers,
        verifiedUsers,
        adminUsers,
        recentUsers
      },
      distribution: {
        roles: roleDistribution,
        verification: {
          verified: verifiedUsers,
          unverified: totalUsers - verifiedUsers
        },
        status: {
          active: activeUsers,
          inactive: totalUsers - activeUsers
        }
      },
      growth: userGrowth
    };

    logger.info('User statistics retrieved', { requestedBy: req.user.id });

    res.status(200).json({
      success: true,
      data: { stats }
    });

  } catch (error) {
    logger.error('Get user stats error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get user by ID
 * @route   GET /api/v1/users/:id
 * @access  Private
 */
const getUserById = async (req, res, next) => {
  try {
    const { id } = req.params;
    const requestingUser = req.user;

    // Check cache first
    const cacheKey = `user_profile:${id}`;
    const cachedUser = await cache.get(cacheKey);
    
    if (cachedUser) {
      return res.status(200).json({
        success: true,
        data: { user: cachedUser },
        cached: true
      });
    }

    // Get user from database
    let user = await User.findById(id)
      .populate('teams', 'name slug memberCount')
      .select('-password')
      .lean();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Filter sensitive information based on requesting user
    if (requestingUser.id !== id && !['admin', 'manager'].includes(requestingUser.role)) {
      // Remove sensitive fields for non-owners/non-admins
      delete user.email;
      delete user.lastLoginAt;
      delete user.lastLoginIP;
      delete user.loginAttempts;
      delete user.lockUntil;
      
      // Apply privacy settings
      if (!user.profile?.preferences?.privacy?.profileVisible) {
        return res.status(403).json({
          success: false,
          message: 'This user profile is private'
        });
      }
    }

    // Get additional user statistics if allowed
    if (requestingUser.id === id || ['admin', 'manager'].includes(requestingUser.role)) {
      const [taskCount, completedTasks] = await Promise.all([
        Task.countDocuments({ createdBy: id }),
        Task.countDocuments({ createdBy: id, status: 'completed' })
      ]);

      user.stats = {
        tasksCreated: taskCount,
        tasksCompleted: completedTasks,
        completionRate: taskCount > 0 ? ((completedTasks / taskCount) * 100).toFixed(1) : 0
      };
    }

    // Cache user data for 10 minutes
    await cache.set(cacheKey, user, 600);

    logger.info('User profile retrieved', {
      targetUser: id,
      requestedBy: requestingUser.id,
      isOwner: requestingUser.id === id
    });

    res.status(200).json({
      success: true,
      data: { user }
    });

  } catch (error) {
    logger.error('Get user by ID error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Update user profile
 * @route   PUT /api/v1/users/:id
 * @access  Private (Owner or Admin)
 */
const updateUser = async (req, res, next) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    const requestingUser = req.user;

    // Remove sensitive fields that shouldn't be updated via this endpoint
    delete updateData.password;
    delete updateData.role;
    delete updateData.emailVerified;
    delete updateData.isActive;

    // Only allow email updates by the user themselves
    if (requestingUser.id !== id) {
      delete updateData.email;
    }

    // Update user
    const user = await User.findByIdAndUpdate(
      id,
      { $set: updateData },
      { new: true, runValidators: true }
    ).select('-password').lean();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Clear cache
    await cache.del(`user_profile:${id}`);
    await cache.del(`user:${id}`);

    logger.business('User profile updated', {
      targetUser: id,
      updatedBy: requestingUser.id,
      updatedFields: Object.keys(updateData)
    });

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: { user }
    });

  } catch (error) {
    logger.error('Update user error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Delete user account
 * @route   DELETE /api/v1/users/:id
 * @access  Private (Owner or Admin)
 */
const deleteUser = async (req, res, next) => {
  try {
    const { id } = req.params;
    const requestingUser = req.user;

    // Prevent self-deletion by admin
    if (requestingUser.id === id && requestingUser.role === 'admin') {
      return res.status(400).json({
        success: false,
        message: 'Admin users cannot delete their own account'
      });
    }

    // Get user to be deleted
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Soft delete: deactivate instead of hard delete
    await User.findByIdAndUpdate(id, {
      isActive: false,
      deletedAt: new Date(),
      deletedBy: requestingUser.id
    });

    // Clear all user caches
    await Promise.all([
      cache.del(`user_profile:${id}`),
      cache.del(`user:${id}`),
      cache.clearPattern(`user_search:*`)
    ]);

    logger.business('User account deleted', {
      targetUser: id,
      deletedBy: requestingUser.id,
      userEmail: user.email
    });

    res.status(200).json({
      success: true,
      message: 'User account has been deactivated'
    });

  } catch (error) {
    logger.error('Delete user error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Upload user avatar
 * @route   POST /api/v1/users/:id/avatar
 * @access  Private (Owner only)
 */
const uploadAvatar = async (req, res, next) => {
  try {
    const { id } = req.params;
    const file = req.file;

    if (!file) {
      return res.status(400).json({
        success: false,
        message: 'No avatar file provided'
      });
    }

    // Get current user to remove old avatar
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Remove old avatar file if exists
    if (user.profile?.avatar) {
      try {
        const oldAvatarPath = path.join(config.upload.uploadPath, 'avatars', path.basename(user.profile.avatar));
        await fs.unlink(oldAvatarPath);
      } catch (unlinkError) {
        logger.warn('Failed to delete old avatar file', unlinkError);
      }
    }

    // Update user with new avatar
    const avatarUrl = `/uploads/avatars/${file.filename}`;
    await User.findByIdAndUpdate(id, {
      'profile.avatar': avatarUrl
    });

    // Clear cache
    await cache.del(`user_profile:${id}`);

    logger.business('User avatar uploaded', {
      userId: id,
      filename: file.filename,
      size: file.size
    });

    res.status(200).json({
      success: true,
      message: 'Avatar uploaded successfully',
      data: {
        avatar: avatarUrl
      }
    });

  } catch (error) {
    logger.error('Upload avatar error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Delete user avatar
 * @route   DELETE /api/v1/users/:id/avatar
 * @access  Private (Owner only)
 */
const deleteAvatar = async (req, res, next) => {
  try {
    const { id } = req.params;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (!user.profile?.avatar) {
      return res.status(400).json({
        success: false,
        message: 'No avatar to delete'
      });
    }

    // Delete avatar file
    try {
      const avatarPath = path.join(config.upload.uploadPath, 'avatars', path.basename(user.profile.avatar));
      await fs.unlink(avatarPath);
    } catch (unlinkError) {
      logger.warn('Failed to delete avatar file', unlinkError, { userId: id });
    }

    // Update user
    await User.findByIdAndUpdate(id, {
      $unset: { 'profile.avatar': 1 }
    });

    // Clear cache
    await cache.del(`user_profile:${id}`);

    logger.business('User avatar deleted', { userId: id });

    res.status(200).json({
      success: true,
      message: 'Avatar deleted successfully'
    });

  } catch (error) {
    logger.error('Delete avatar error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get user's tasks
 * @route   GET /api/v1/users/:id/tasks
 * @access  Private (Owner or Admin)
 */
const getUserTasks = async (req, res, next) => {
  try {
    const { id } = req.params;
    const {
      page = 1,
      limit = 10,
      status,
      priority,
      sort = '-createdAt'
    } = req.query;

    // Build filter
    const filter = { createdBy: id };
    if (status) filter.status = status;
    if (priority) filter.priority = priority;

    // Calculate pagination
    const skip = (page - 1) * parseInt(limit);
    const limitNum = parseInt(limit);

    // Get tasks and total count
    const [tasks, total] = await Promise.all([
      Task.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(limitNum)
        .populate('assignedTo', 'firstName lastName username')
        .lean(),
      Task.countDocuments(filter)
    ]);

    const totalPages = Math.ceil(total / limitNum);

    res.status(200).json({
      success: true,
      data: {
        tasks,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalTasks: total,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
          limit: limitNum
        }
      }
    });

  } catch (error) {
    logger.error('Get user tasks error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get user's activity log
 * @route   GET /api/v1/users/:id/activity
 * @access  Private (Owner or Admin)
 */
const getUserActivity = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    // This would typically come from an activity/audit log collection
    // For now, return a placeholder response
    res.status(200).json({
      success: true,
      data: {
        activities: [],
        message: 'Activity logging not yet implemented'
      }
    });

  } catch (error) {
    logger.error('Get user activity error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Update user status (active/inactive)
 * @route   PUT /api/v1/users/:id/status
 * @access  Private (Admin only)
 */
const updateUserStatus = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    const user = await User.findByIdAndUpdate(
      id,
      { isActive },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Clear cache
    await cache.del(`user_profile:${id}`);

    logger.business('User status updated', {
      targetUser: id,
      updatedBy: req.user.id,
      newStatus: isActive ? 'active' : 'inactive'
    });

    res.status(200).json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
      data: { user }
    });

  } catch (error) {
    logger.error('Update user status error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Update user role
 * @route   PUT /api/v1/users/:id/role
 * @access  Private (Admin only)
 */
const updateUserRole = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    // Prevent changing own role
    if (req.user.id === id) {
      return res.status(400).json({
        success: false,
        message: 'Cannot change your own role'
      });
    }

    const user = await User.findByIdAndUpdate(
      id,
      { role },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Clear cache
    await cache.del(`user_profile:${id}`);

    logger.business('User role updated', {
      targetUser: id,
      updatedBy: req.user.id,
      newRole: role
    });

    res.status(200).json({
      success: true,
      message: 'User role updated successfully',
      data: { user }
    });

  } catch (error) {
    logger.error('Update user role error', error, { userId: req.user?.id });
    next(error);
  }
};

// Placeholder functions for features to be implemented
const followUser = async (req, res) => {
  res.status(501).json({ success: false, message: 'Follow feature not yet implemented' });
};

const unfollowUser = async (req, res) => {
  res.status(501).json({ success: false, message: 'Unfollow feature not yet implemented' });
};

const getUserFollowers = async (req, res) => {
  res.status(501).json({ success: false, message: 'Followers feature not yet implemented' });
};

const getUserFollowing = async (req, res) => {
  res.status(501).json({ success: false, message: 'Following feature not yet implemented' });
};

const getUserPreferences = async (req, res) => {
  res.status(501).json({ success: false, message: 'Preferences feature not yet implemented' });
};

const updateUserPreferences = async (req, res) => {
  res.status(501).json({ success: false, message: 'Update preferences feature not yet implemented' });
};

const getUserNotifications = async (req, res) => {
  res.status(501).json({ success: false, message: 'Notifications feature not yet implemented' });
};

const markNotificationRead = async (req, res) => {
  res.status(501).json({ success: false, message: 'Mark notification read not yet implemented' });
};

const deleteNotification = async (req, res) => {
  res.status(501).json({ success: false, message: 'Delete notification not yet implemented' });
};

const exportUserData = async (req, res) => {
  res.status(501).json({ success: false, message: 'Data export not yet implemented' });
};

const deactivateAccount = async (req, res) => {
  res.status(501).json({ success: false, message: 'Account deactivation not yet implemented' });
};

const reactivateAccount = async (req, res) => {
  res.status(501).json({ success: false, message: 'Account reactivation not yet implemented' });
};

const getUserTeams = async (req, res) => {
  res.status(501).json({ success: false, message: 'Teams feature not yet implemented' });
};

const joinTeam = async (req, res) => {
  res.status(501).json({ success: false, message: 'Join team not yet implemented' });
};

const leaveTeam = async (req, res) => {
  res.status(501).json({ success: false, message: 'Leave team not yet implemented' });
};

const bulkInviteUsers = async (req, res) => {
  res.status(501).json({ success: false, message: 'Bulk invite not yet implemented' });
};

const bulkUpdateUsers = async (req, res) => {
  res.status(501).json({ success: false, message: 'Bulk update not yet implemented' });
};

const bulkDeleteUsers = async (req, res) => {
  res.status(501).json({ success: false, message: 'Bulk delete not yet implemented' });
};

module.exports = {
  getUsers,
  searchUsers,
  getUserStats,
  getUserById,
  updateUser,
  deleteUser,
  uploadAvatar,
  deleteAvatar,
  getUserTasks,
  getUserActivity,
  updateUserStatus,
  updateUserRole,
  followUser,
  unfollowUser,
  getUserFollowers,
  getUserFollowing,
  getUserPreferences,
  updateUserPreferences,
  getUserNotifications,
  markNotificationRead,
  deleteNotification,
  exportUserData,
  deactivateAccount,
  reactivateAccount,
  getUserTeams,
  joinTeam,
  leaveTeam,
  bulkInviteUsers,
  bulkUpdateUsers,
  bulkDeleteUsers
};