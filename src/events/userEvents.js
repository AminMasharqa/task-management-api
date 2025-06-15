/**
 * User Events
 * Event-driven user operations and side effects
 */

const EventEmitter = require('events');
const User = require('../models/User');
const Task = require('../models/Task');
const notificationService = require('../services/notification.service');
const { cache, pubsub } = require('../config/redis');
const { USER_ROLES, NOTIFICATION_TYPES } = require('../utils/constants');
const logger = require('../utils/logger');

class UserEventEmitter extends EventEmitter {}
const userEvents = new UserEventEmitter();

/**
 * User Registered Event
 */
userEvents.on('user:registered', async (user, registrationData) => {
  try {
    logger.business('User registered event triggered', {
      userId: user._id,
      email: user.email,
      username: user.username
    });

    // Send welcome email
    await notificationService.sendWelcomeEmail(user);

    // Log security event
    user.addSecurityEvent('login', {
      ip: registrationData.ip,
      userAgent: registrationData.userAgent,
      method: 'registration'
    });
    await user.save();

    // Initialize user analytics
    userEvents.emit('analytics:user_registered', {
      userId: user._id,
      registrationDate: user.createdAt,
      source: registrationData.source || 'direct'
    });

  } catch (error) {
    logger.error('Error handling user registered event', error, {
      userId: user._id
    });
  }
});

/**
 * User Login Event
 */
userEvents.on('user:login', async (user, loginData) => {
  try {
    logger.business('User login event triggered', {
      userId: user._id,
      email: user.email,
      ip: loginData.ip
    });

    // Update user online status and last login
    await User.findByIdAndUpdate(user._id, {
      isOnline: true,
      lastLoginAt: new Date(),
      lastLoginIP: loginData.ip,
      lastSeenAt: new Date()
    });

    // Log security event
    const userData = await User.findById(user._id);
    userData.addSecurityEvent('login', {
      ip: loginData.ip,
      userAgent: loginData.userAgent,
      sessionId: loginData.sessionId
    });
    await userData.save();

    // Broadcast user online status
    await pubsub.publish('user:online', {
      userId: user._id,
      timestamp: new Date()
    });

    // Clear user caches
    await clearUserCaches(user._id);

  } catch (error) {
    logger.error('Error handling user login event', error, {
      userId: user._id
    });
  }
});

/**
 * User Logout Event
 */
userEvents.on('user:logout', async (user, logoutData) => {
  try {
    logger.business('User logout event triggered', {
      userId: user._id,
      sessionId: logoutData.sessionId
    });

    // Update user offline status
    await User.findByIdAndUpdate(user._id, {
      isOnline: false,
      lastSeenAt: new Date()
    });

    // Log security event
    const userData = await User.findById(user._id);
    userData.addSecurityEvent('logout', {
      ip: logoutData.ip,
      userAgent: logoutData.userAgent,
      sessionId: logoutData.sessionId
    });
    await userData.save();

    // Broadcast user offline status
    await pubsub.publish('user:offline', {
      userId: user._id,
      timestamp: new Date()
    });

    // Clear user caches
    await clearUserCaches(user._id);

  } catch (error) {
    logger.error('Error handling user logout event', error, {
      userId: user._id
    });
  }
});

/**
 * User Profile Updated Event
 */
userEvents.on('user:profile_updated', async (user, updatedFields, updater) => {
  try {
    logger.business('User profile updated event triggered', {
      userId: user._id,
      updatedBy: updater._id,
      updatedFields
    });

    // Clear user profile caches
    await clearUserCaches(user._id);

    // If email was updated, trigger email verification
    if (updatedFields.includes('email')) {
      userEvents.emit('user:email_changed', user, updater);
    }

    // If role was updated, handle role change
    if (updatedFields.includes('role')) {
      userEvents.emit('user:role_changed', user, updater);
    }

    // Analytics event
    userEvents.emit('analytics:profile_updated', {
      userId: user._id,
      updatedFields,
      updatedBy: updater._id,
      timestamp: new Date()
    });

  } catch (error) {
    logger.error('Error handling profile updated event', error, {
      userId: user._id
    });
  }
});

/**
 * User Email Changed Event
 */
userEvents.on('user:email_changed', async (user, updater) => {
  try {
    logger.security('User email changed', {
      userId: user._id,
      newEmail: user.email,
      changedBy: updater._id
    });

    // Reset email verification
    await User.findByIdAndUpdate(user._id, {
      emailVerified: false
    });

    // Send new verification email
    const verificationToken = require('crypto').randomBytes(32).toString('hex');
    await User.findByIdAndUpdate(user._id, {
      emailVerificationToken: verificationToken,
      emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });

    await notificationService.sendEmailVerification(user, verificationToken);

    // Log security event
    const userData = await User.findById(user._id);
    userData.addSecurityEvent('email_change', {
      newEmail: user.email,
      changedBy: updater._id
    });
    await userData.save();

  } catch (error) {
    logger.error('Error handling email changed event', error, {
      userId: user._id
    });
  }
});

/**
 * User Role Changed Event
 */
userEvents.on('user:role_changed', async (user, updater) => {
  try {
    logger.security('User role changed', {
      userId: user._id,
      newRole: user.role,
      changedBy: updater._id
    });

    // Send role change notification
    await notificationService.sendRealTimeNotification(
      user._id,
      NOTIFICATION_TYPES.SYSTEM,
      {
        type: 'role_changed',
        newRole: user.role,
        message: `Your role has been updated to ${user.role}`,
        changedBy: updater.firstName + ' ' + updater.lastName
      }
    );

    // Log security event
    const userData = await User.findById(user._id);
    userData.addSecurityEvent('role_changed', {
      newRole: user.role,
      changedBy: updater._id
    });
    await userData.save();

    // If promoted to admin, send welcome message
    if (user.role === USER_ROLES.ADMIN) {
      await notificationService.sendRealTimeNotification(
        user._id,
        NOTIFICATION_TYPES.SYSTEM,
        {
          type: 'admin_promotion',
          message: 'Congratulations! You now have administrator privileges.',
          features: ['User management', 'System configuration', 'Analytics access']
        }
      );
    }

  } catch (error) {
    logger.error('Error handling role changed event', error, {
      userId: user._id
    });
  }
});

/**
 * User Password Changed Event
 */
userEvents.on('user:password_changed', async (user, changeData) => {
  try {
    logger.security('User password changed', {
      userId: user._id,
      ip: changeData.ip
    });

    // Log security event
    const userData = await User.findById(user._id);
    userData.addSecurityEvent('password_change', {
      ip: changeData.ip,
      userAgent: changeData.userAgent,
      timestamp: new Date()
    });
    await userData.save();

    // Send security notification
    await notificationService.sendRealTimeNotification(
      user._id,
      NOTIFICATION_TYPES.SYSTEM,
      {
        type: 'password_changed',
        message: 'Your password has been changed successfully',
        timestamp: new Date(),
        ip: changeData.ip
      }
    );

  } catch (error) {
    logger.error('Error handling password changed event', error, {
      userId: user._id
    });
  }
});

/**
 * User Deactivated Event
 */
userEvents.on('user:deactivated', async (user, deactivator, reason) => {
  try {
    logger.business('User deactivated event triggered', {
      userId: user._id,
      deactivatedBy: deactivator._id,
      reason
    });

    // Reassign tasks if needed
    const activeTasks = await Task.find({
      assignedTo: user._id,
      status: { $nin: ['completed', 'cancelled'] },
      isDeleted: false
    });

    if (activeTasks.length > 0) {
      // For now, just remove the user from assignments
      // In a real app, you might want to reassign to a manager
      await Task.updateMany(
        { assignedTo: user._id },
        { $pull: { assignedTo: user._id } }
      );

      logger.info('Tasks updated for deactivated user', {
        userId: user._id,
        taskCount: activeTasks.length
      });
    }

    // Clear all user caches
    await clearUserCaches(user._id);

    // Broadcast user deactivation
    await pubsub.publish('user:deactivated', {
      userId: user._id,
      timestamp: new Date()
    });

  } catch (error) {
    logger.error('Error handling user deactivated event', error, {
      userId: user._id
    });
  }
});

/**
 * User Followed Event
 */
userEvents.on('user:followed', async (follower, followedUser) => {
  try {
    logger.business('User followed event triggered', {
      followerId: follower._id,
      followedUserId: followedUser._id
    });

    // Send notification to followed user
    await notificationService.sendRealTimeNotification(
      followedUser._id,
      NOTIFICATION_TYPES.SYSTEM,
      {
        type: 'new_follower',
        message: `${follower.firstName} ${follower.lastName} started following you`,
        follower: {
          id: follower._id,
          name: follower.firstName + ' ' + follower.lastName,
          username: follower.username,
          avatar: follower.profile?.avatar
        }
      }
    );

    // Clear follower caches
    await cache.del(`user_followers:${followedUser._id}`);
    await cache.del(`user_following:${follower._id}`);

  } catch (error) {
    logger.error('Error handling user followed event', error, {
      followerId: follower._id,
      followedUserId: followedUser._id
    });
  }
});

/**
 * User Account Locked Event
 */
userEvents.on('user:account_locked', async (user, lockData) => {
  try {
    logger.security('User account locked', {
      userId: user._id,
      reason: lockData.reason,
      attempts: lockData.attempts
    });

    // Log security event
    const userData = await User.findById(user._id);
    userData.addSecurityEvent('account_locked', {
      reason: lockData.reason,
      attempts: lockData.attempts,
      lockUntil: lockData.lockUntil
    });
    await userData.save();

    // Send security alert email
    try {
      await notificationService.sendEmail(
        user.email,
        'Account Temporarily Locked',
        'account-locked',
        {
          firstName: user.firstName,
          lockReason: lockData.reason,
          unlockTime: new Date(lockData.lockUntil).toLocaleString()
        }
      );
    } catch (emailError) {
      logger.error('Failed to send account locked email', emailError);
    }

  } catch (error) {
    logger.error('Error handling account locked event', error, {
      userId: user._id
    });
  }
});

/**
 * Analytics Events
 */
userEvents.on('analytics:user_registered', async (data) => {
  try {
    const analyticsKey = `analytics:user_registration:${new Date().toISOString().split('T')[0]}`;
    const analytics = await cache.get(analyticsKey) || [];
    
    analytics.push({
      ...data,
      timestamp: new Date()
    });
    
    await cache.set(analyticsKey, analytics, 30 * 24 * 60 * 60); // 30 days

    logger.info('User registration analytics recorded', data);

  } catch (error) {
    logger.error('Error recording user registration analytics', error);
  }
});

userEvents.on('analytics:profile_updated', async (data) => {
  try {
    const analyticsKey = `analytics:profile_updates:${new Date().toISOString().split('T')[0]}`;
    const analytics = await cache.get(analyticsKey) || [];
    
    analytics.push(data);
    await cache.set(analyticsKey, analytics, 7 * 24 * 60 * 60); // 7 days

  } catch (error) {
    logger.error('Error recording profile update analytics', error);
  }
});

/**
 * Clear user-related caches
 */
const clearUserCaches = async (userId) => {
  try {
    const cacheKeys = [
      `user_profile:${userId}`,
      `user:${userId}`,
      `user_sessions:${userId}`,
      `user_notifications:${userId}`,
      `user_followers:${userId}`,
      `user_following:${userId}`,
      `overdue_tasks:${userId}`,
      `task_stats:${userId}`
    ];

    await Promise.all(cacheKeys.map(key => cache.del(key)));

    // Clear search caches
    await cache.clearPattern('user_search:*');

  } catch (error) {
    logger.error('Error clearing user caches', error, { userId });
  }
};

/**
 * Initialize user event listeners
 */
const initializeUserEvents = () => {
  logger.info('✅ User events initialized');
  
  // Set max listeners to prevent memory leaks
  userEvents.setMaxListeners(50);
  
  return userEvents;
};

module.exports = {
  userEvents,
  initializeUserEvents
};