/**
 * Notification Service
 * Email notifications, real-time alerts, and communication features
 */

const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');
const User = require('../models/User');
const { cache, pubsub } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Email transporter instance
 */
let emailTransporter = null;

/**
 * Email templates cache
 */
const templateCache = new Map();

/**
 * Initialize email transporter
 */
const initializeEmailTransporter = () => {
  try {
    if (config.email.mockService) {
      // Mock transporter for development/testing
      emailTransporter = {
        sendMail: async (mailOptions) => {
          logger.info('Mock email sent', {
            to: mailOptions.to,
            subject: mailOptions.subject,
            template: mailOptions.template || 'custom'
          });
          return { messageId: `mock-${Date.now()}` };
        }
      };
    } else {
      // Real SMTP transporter
      emailTransporter = nodemailer.createTransporter({
        host: config.email.smtp.host,
        port: config.email.smtp.port,
        secure: config.email.smtp.secure,
        auth: {
          user: config.email.smtp.auth.user,
          pass: config.email.smtp.auth.pass
        },
        pool: true,
        maxConnections: 5,
        maxMessages: 100,
        rateDelta: 1000,
        rateLimit: 10
      });

      // Verify SMTP connection
      emailTransporter.verify((error) => {
        if (error) {
          logger.error('SMTP connection failed', error);
        } else {
          logger.info('✅ SMTP connection established');
        }
      });
    }

    return emailTransporter;
  } catch (error) {
    logger.error('Failed to initialize email transporter', error);
    throw error;
  }
};

/**
 * Load email template
 */
const loadEmailTemplate = async (templateName, variables = {}) => {
  try {
    // Check cache first
    const cacheKey = `template:${templateName}`;
    let template = templateCache.get(cacheKey);

    if (!template) {
      // Load template from file system
      const templatePath = path.join(__dirname, '..', 'templates', 'email', `${templateName}.html`);
      
      try {
        template = await fs.readFile(templatePath, 'utf8');
        templateCache.set(cacheKey, template);
      } catch (fileError) {
        // Fallback to basic template
        template = getBasicTemplate(templateName);
        templateCache.set(cacheKey, template);
      }
    }

    // Replace variables in template
    let processedTemplate = template;
    Object.keys(variables).forEach(key => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      processedTemplate = processedTemplate.replace(regex, variables[key]);
    });

    // Replace common variables
    processedTemplate = processedTemplate.replace(/{{APP_NAME}}/g, 'Task Manager');
    processedTemplate = processedTemplate.replace(/{{SUPPORT_EMAIL}}/g, config.email.from.email);
    processedTemplate = processedTemplate.replace(/{{CURRENT_YEAR}}/g, new Date().getFullYear());

    return processedTemplate;

  } catch (error) {
    logger.error('Failed to load email template', error, { templateName });
    return getBasicTemplate(templateName, variables);
  }
};

/**
 * Get basic fallback template
 */
const getBasicTemplate = (templateName, variables = {}) => {
  const templates = {
    'email-verification': `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Verify Your Email Address</h2>
        <p>Hello {{firstName}},</p>
        <p>Thank you for signing up! Please click the button below to verify your email address:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{verificationUrl}}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            Verify Email
          </a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p><a href="{{verificationUrl}}">{{verificationUrl}}</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">{{APP_NAME}} Team</p>
      </div>
    `,
    'password-reset': `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Password Reset Request</h2>
        <p>Hello {{firstName}},</p>
        <p>We received a request to reset your password. Click the button below to reset it:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{resetUrl}}" style="background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            Reset Password
          </a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p><a href="{{resetUrl}}">{{resetUrl}}</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request a password reset, you can safely ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">{{APP_NAME}} Team</p>
      </div>
    `,
    'task-assigned': `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>New Task Assignment</h2>
        <p>Hello {{firstName}},</p>
        <p>You have been assigned a new task:</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 4px; margin: 20px 0;">
          <h3 style="margin: 0 0 10px 0;">{{taskTitle}}</h3>
          <p style="margin: 0 0 10px 0; color: #666;">{{taskDescription}}</p>
          <p style="margin: 0;"><strong>Priority:</strong> {{taskPriority}}</p>
          <p style="margin: 0;"><strong>Due Date:</strong> {{taskDueDate}}</p>
        </div>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{taskUrl}}" style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            View Task
          </a>
        </div>
        <p>Assigned by: {{assignedBy}}</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">{{APP_NAME}} Team</p>
      </div>
    `,
    'task-completed': `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Task Completed! 🎉</h2>
        <p>Hello {{firstName}},</p>
        <p>Great news! A task has been completed:</p>
        <div style="background: #d4edda; padding: 20px; border-radius: 4px; margin: 20px 0; border-left: 4px solid #28a745;">
          <h3 style="margin: 0 0 10px 0;">{{taskTitle}}</h3>
          <p style="margin: 0;"><strong>Completed by:</strong> {{completedBy}}</p>
          <p style="margin: 0;"><strong>Completion Date:</strong> {{completedDate}}</p>
        </div>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{taskUrl}}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            View Task
          </a>
        </div>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">{{APP_NAME}} Team</p>
      </div>
    `,
    'welcome': `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome to {{APP_NAME}}! 🎉</h2>
        <p>Hello {{firstName}},</p>
        <p>Welcome to our task management platform! We're excited to have you on board.</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 4px; margin: 20px 0;">
          <h3>Getting Started:</h3>
          <ul>
            <li>Create your first task</li>
            <li>Invite team members</li>
            <li>Set up your profile</li>
            <li>Explore our features</li>
          </ul>
        </div>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{dashboardUrl}}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            Go to Dashboard
          </a>
        </div>
        <p>If you have any questions, feel free to reach out to our support team.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">{{APP_NAME}} Team</p>
      </div>
    `
  };

  let template = templates[templateName] || `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>{{subject}}</h2>
      <p>{{message}}</p>
      <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
      <p style="color: #666; font-size: 12px;">{{APP_NAME}} Team</p>
    </div>
  `;

  // Replace variables
  Object.keys(variables).forEach(key => {
    const regex = new RegExp(`{{${key}}}`, 'g');
    template = template.replace(regex, variables[key]);
  });

  return template;
};

/**
 * Send email notification
 */
const sendEmail = async (to, subject, templateName, variables = {}, attachments = []) => {
  try {
    if (!emailTransporter) {
      initializeEmailTransporter();
    }

    // Get user preferences if recipient is a user ID
    let recipient = to;
    let userPreferences = null;
    
    if (to.match(/^[0-9a-fA-F]{24}$/)) {
      // It's a user ID, get email and preferences
      const user = await User.findById(to).select('email firstName lastName profile.preferences');
      if (!user) {
        throw new Error('User not found');
      }
      recipient = user.email;
      userPreferences = user.profile?.preferences?.notifications;
      
      // Add user data to variables
      variables.firstName = variables.firstName || user.firstName;
      variables.lastName = variables.lastName || user.lastName;
      variables.fullName = `${user.firstName} ${user.lastName}`;
    }

    // Check if user has email notifications enabled
    if (userPreferences && !userPreferences.email) {
      logger.info('Email notification skipped - user preference disabled', { 
        recipient,
        templateName 
      });
      return { skipped: true, reason: 'user_preference' };
    }

    // Load and process template
    const htmlContent = await loadEmailTemplate(templateName, variables);

    // Prepare email options
    const mailOptions = {
      from: {
        name: config.email.from.name,
        address: config.email.from.email
      },
      to: recipient,
      subject,
      html: htmlContent,
      attachments,
      headers: {
        'X-Mailer': 'Task Management API',
        'X-Template': templateName
      }
    };

    // Send email
    const result = await emailTransporter.sendMail(mailOptions);

    // Log successful send
    logger.info('Email sent successfully', {
      to: recipient,
      subject,
      template: templateName,
      messageId: result.messageId
    });

    // Cache notification for analytics
    await cacheNotificationEvent('email', {
      recipient,
      subject,
      template: templateName,
      sentAt: new Date(),
      messageId: result.messageId
    });

    return {
      success: true,
      messageId: result.messageId,
      recipient
    };

  } catch (error) {
    logger.error('Failed to send email', error, {
      to,
      subject,
      template: templateName
    });

    // Cache failed notification for retry logic
    await cacheFailedNotification('email', {
      recipient: to,
      subject,
      template: templateName,
      error: error.message,
      failedAt: new Date()
    });

    throw new Error(`Email sending failed: ${error.message}`);
  }
};

/**
 * Send real-time notification via WebSocket
 */
const sendRealTimeNotification = async (userId, type, data) => {
  try {
    // Get user preferences
    const user = await User.findById(userId).select('profile.preferences');
    const preferences = user?.profile?.preferences?.notifications;

    // Check if user has real-time notifications enabled
    if (preferences && !preferences.push) {
      logger.info('Real-time notification skipped - user preference disabled', { 
        userId,
        type 
      });
      return { skipped: true, reason: 'user_preference' };
    }

    const notification = {
      id: require('uuid').v4(),
      userId,
      type,
      data,
      timestamp: new Date(),
      read: false
    };

    // Store notification in database/cache for persistence
    await storeNotification(notification);

    // Publish to real-time channel
    await pubsub.publish(`user:${userId}:notifications`, notification);

    // Also publish to general notification channel
    await pubsub.publish('notifications:new', {
      userId,
      notification
    });

    logger.info('Real-time notification sent', {
      userId,
      type,
      notificationId: notification.id
    });

    return {
      success: true,
      notificationId: notification.id
    };

  } catch (error) {
    logger.error('Failed to send real-time notification', error, {
      userId,
      type
    });
    throw error;
  }
};

/**
 * Store notification for user's notification center
 */
const storeNotification = async (notification) => {
  try {
    const userNotificationsKey = `notifications:${notification.userId}`;
    const existingNotifications = await cache.get(userNotificationsKey) || [];
    
    // Add new notification to the beginning
    existingNotifications.unshift(notification);
    
    // Keep only last 100 notifications
    if (existingNotifications.length > 100) {
      existingNotifications.splice(100);
    }
    
    // Store with 30 day TTL
    await cache.set(userNotificationsKey, existingNotifications, 30 * 24 * 60 * 60);

  } catch (error) {
    logger.error('Failed to store notification', error);
  }
};

/**
 * Get user notifications
 */
const getUserNotifications = async (userId, options = {}) => {
  try {
    const { limit = 20, offset = 0, unreadOnly = false } = options;
    
    const userNotificationsKey = `notifications:${userId}`;
    const notifications = await cache.get(userNotificationsKey) || [];
    
    let filteredNotifications = notifications;
    
    if (unreadOnly) {
      filteredNotifications = notifications.filter(n => !n.read);
    }
    
    // Apply pagination
    const paginatedNotifications = filteredNotifications.slice(offset, offset + limit);
    
    return {
      notifications: paginatedNotifications,
      total: filteredNotifications.length,
      unreadCount: notifications.filter(n => !n.read).length
    };

  } catch (error) {
    logger.error('Failed to get user notifications', error, { userId });
    return { notifications: [], total: 0, unreadCount: 0 };
  }
};

/**
 * Mark notification as read
 */
const markNotificationRead = async (userId, notificationId) => {
  try {
    const userNotificationsKey = `notifications:${userId}`;
    const notifications = await cache.get(userNotificationsKey) || [];
    
    const notification = notifications.find(n => n.id === notificationId);
    if (notification) {
      notification.read = true;
      notification.readAt = new Date();
      
      await cache.set(userNotificationsKey, notifications, 30 * 24 * 60 * 60);
      
      logger.info('Notification marked as read', { userId, notificationId });
      return true;
    }
    
    return false;

  } catch (error) {
    logger.error('Failed to mark notification as read', error, { userId, notificationId });
    return false;
  }
};

/**
 * Delete notification
 */
const deleteNotification = async (userId, notificationId) => {
  try {
    const userNotificationsKey = `notifications:${userId}`;
    const notifications = await cache.get(userNotificationsKey) || [];
    
    const updatedNotifications = notifications.filter(n => n.id !== notificationId);
    
    if (updatedNotifications.length !== notifications.length) {
      await cache.set(userNotificationsKey, updatedNotifications, 30 * 24 * 60 * 60);
      logger.info('Notification deleted', { userId, notificationId });
      return true;
    }
    
    return false;

  } catch (error) {
    logger.error('Failed to delete notification', error, { userId, notificationId });
    return false;
  }
};

/**
 * Cache notification event for analytics
 */
const cacheNotificationEvent = async (type, data) => {
  try {
    const event = {
      type,
      data,
      timestamp: new Date()
    };
    
    const eventsKey = `notification_events:${new Date().toISOString().split('T')[0]}`;
    const existingEvents = await cache.get(eventsKey) || [];
    existingEvents.push(event);
    
    // Store for 7 days
    await cache.set(eventsKey, existingEvents, 7 * 24 * 60 * 60);

  } catch (error) {
    logger.error('Failed to cache notification event', error);
  }
};

/**
 * Cache failed notification for retry
 */
const cacheFailedNotification = async (type, data) => {
  try {
    const failedNotification = {
      type,
      data,
      timestamp: new Date(),
      retryCount: 0
    };
    
    const failedKey = `failed_notifications:${type}`;
    const failedNotifications = await cache.get(failedKey) || [];
    failedNotifications.push(failedNotification);
    
    // Store for 24 hours
    await cache.set(failedKey, failedNotifications, 24 * 60 * 60);

  } catch (error) {
    logger.error('Failed to cache failed notification', error);
  }
};

/**
 * Specific notification methods for different events
 */

/**
 * Send email verification
 */
const sendEmailVerification = async (user, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${token}`;
  
  return sendEmail(
    user.email,
    'Verify Your Email Address',
    'email-verification',
    {
      firstName: user.firstName,
      verificationUrl
    }
  );
};

/**
 * Send password reset email
 */
const sendPasswordReset = async (user, token) => {
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${token}`;
  
  return sendEmail(
    user.email,
    'Password Reset Request',
    'password-reset',
    {
      firstName: user.firstName,
      resetUrl
    }
  );
};

/**
 * Send welcome email
 */
const sendWelcomeEmail = async (user) => {
  const dashboardUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard`;
  
  return sendEmail(
    user.email,
    'Welcome to Task Manager!',
    'welcome',
    {
      firstName: user.firstName,
      dashboardUrl
    }
  );
};

/**
 * Notify task assignment
 */
const notifyTaskAssignment = async (task, assignedBy) => {
  try {
    const taskUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/tasks/${task._id}`;
    
    // Email notifications to assigned users
    const emailPromises = task.assignedTo.map(async (assignee) => {
      return sendEmail(
        assignee._id,
        `New Task Assignment: ${task.title}`,
        'task-assigned',
        {
          firstName: assignee.firstName,
          taskTitle: task.title,
          taskDescription: task.description || 'No description',
          taskPriority: task.priority,
          taskDueDate: task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No due date',
          taskUrl,
          assignedBy: assignedBy.firstName + ' ' + assignedBy.lastName
        }
      );
    });

    // Real-time notifications
    const realtimePromises = task.assignedTo.map(assignee => 
      sendRealTimeNotification(assignee._id, 'task_assigned', {
        task: {
          id: task._id,
          title: task.title,
          priority: task.priority
        },
        assignedBy: {
          id: assignedBy.id,
          name: assignedBy.firstName + ' ' + assignedBy.lastName
        }
      })
    );

    await Promise.all([...emailPromises, ...realtimePromises]);

    logger.info('Task assignment notifications sent', {
      taskId: task._id,
      assignedTo: task.assignedTo.map(u => u._id),
      assignedBy: assignedBy.id
    });

  } catch (error) {
    logger.error('Failed to send task assignment notifications', error);
  }
};

/**
 * Notify task update
 */
const notifyTaskUpdate = async (task, updatedBy, changes) => {
  try {
    // Determine who should be notified
    const notifyUsers = new Set();
    
    // Add task creator
    if (task.createdBy && !task.createdBy.equals(updatedBy.id)) {
      notifyUsers.add(task.createdBy.toString());
    }
    
    // Add assigned users
    task.assignedTo?.forEach(user => {
      if (!user.equals(updatedBy.id)) {
        notifyUsers.add(user.toString());
      }
    });
    
    // Add collaborators
    task.collaborators?.forEach(user => {
      if (!user.equals(updatedBy.id)) {
        notifyUsers.add(user.toString());
      }
    });

    // Send real-time notifications
    const notifications = Array.from(notifyUsers).map(userId =>
      sendRealTimeNotification(userId, 'task_updated', {
        task: {
          id: task._id,
          title: task.title
        },
        updatedBy: {
          id: updatedBy.id,
          name: updatedBy.firstName + ' ' + updatedBy.lastName
        },
        changes: Object.keys(changes)
      })
    );

    await Promise.all(notifications);

    logger.info('Task update notifications sent', {
      taskId: task._id,
      updatedBy: updatedBy.id,
      notifiedUsers: Array.from(notifyUsers),
      changes: Object.keys(changes)
    });

  } catch (error) {
    logger.error('Failed to send task update notifications', error);
  }
};

/**
 * Notify task completion
 */
const notifyTaskCompletion = async (task, completedBy) => {
  try {
    const taskUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/tasks/${task._id}`;
    
    // Notify task creator if different from completer
    if (task.createdBy && !task.createdBy.equals(completedBy.id)) {
      await Promise.all([
        sendEmail(
          task.createdBy,
          `Task Completed: ${task.title}`,
          'task-completed',
          {
            taskTitle: task.title,
            completedBy: completedBy.firstName + ' ' + completedBy.lastName,
            completedDate: new Date().toLocaleDateString(),
            taskUrl
          }
        ),
        sendRealTimeNotification(task.createdBy, 'task_completed', {
          task: {
            id: task._id,
            title: task.title
          },
          completedBy: {
            id: completedBy.id,
            name: completedBy.firstName + ' ' + completedBy.lastName
          }
        })
      ]);
    }

    logger.info('Task completion notifications sent', {
      taskId: task._id,
      completedBy: completedBy.id,
      createdBy: task.createdBy
    });

  } catch (error) {
    logger.error('Failed to send task completion notifications', error);
  }
};

/**
 * Notify task status change
 */
const notifyStatusChange = async (task, changedBy, newStatus) => {
  try {
    // Only notify for significant status changes
    const significantStatuses = ['completed', 'cancelled', 'in-progress'];
    
    if (!significantStatuses.includes(newStatus)) {
      return;
    }

    const notifyUsers = new Set();
    
    if (task.createdBy && !task.createdBy.equals(changedBy.id)) {
      notifyUsers.add(task.createdBy.toString());
    }
    
    task.assignedTo?.forEach(user => {
      if (!user.equals(changedBy.id)) {
        notifyUsers.add(user.toString());
      }
    });

    const notifications = Array.from(notifyUsers).map(userId =>
      sendRealTimeNotification(userId, 'task_status_changed', {
        task: {
          id: task._id,
          title: task.title,
          newStatus
        },
        changedBy: {
          id: changedBy.id,
          name: changedBy.firstName + ' ' + changedBy.lastName
        }
      })
    );

    await Promise.all(notifications);

  } catch (error) {
    logger.error('Failed to send status change notifications', error);
  }
};

/**
 * Notify high priority task
 */
const notifyHighPriorityTask = async (task, setBy) => {
  try {
    const notifyUsers = new Set();
    
    task.assignedTo?.forEach(user => {
      notifyUsers.add(user.toString());
    });

    const notifications = Array.from(notifyUsers).map(userId =>
      sendRealTimeNotification(userId, 'high_priority_task', {
        task: {
          id: task._id,
          title: task.title,
          priority: task.priority
        },
        setBy: {
          id: setBy.id,
          name: setBy.firstName + ' ' + setBy.lastName
        }
      })
    );

    await Promise.all(notifications);

  } catch (error) {
    logger.error('Failed to send high priority notifications', error);
  }
};

/**
 * Notify task deletion
 */
const notifyTaskDeletion = async (task, deletedBy) => {
  try {
    const notifyUsers = new Set();
    
    if (task.createdBy && !task.createdBy.equals(deletedBy.id)) {
      notifyUsers.add(task.createdBy.toString());
    }
    
    task.assignedTo?.forEach(user => {
      if (!user.equals(deletedBy.id)) {
        notifyUsers.add(user.toString());
      }
    });

    const notifications = Array.from(notifyUsers).map(userId =>
      sendRealTimeNotification(userId, 'task_deleted', {
        task: {
          id: task._id,
          title: task.title
        },
        deletedBy: {
          id: deletedBy.id,
          name: deletedBy.firstName + ' ' + deletedBy.lastName
        }
      })
    );

    await Promise.all(notifications);

  } catch (error) {
    logger.error('Failed to send task deletion notifications', error);
  }
};

/**
 * Get notification statistics
 */
const getNotificationStats = async () => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const eventsKey = `notification_events:${today}`;
    const events = await cache.get(eventsKey) || [];
    
    const stats = {
      today: {
        total: events.length,
        email: events.filter(e => e.type === 'email').length,
        realtime: events.filter(e => e.type === 'realtime').length
      },
      timestamp: new Date()
    };

    return stats;

  } catch (error) {
    logger.error('Failed to get notification stats', error);
    return { today: { total: 0, email: 0, realtime: 0 }, timestamp: new Date() };
  }
};

/**
 * Retry failed notifications
 */
const retryFailedNotifications = async () => {
  try {
    const types = ['email'];
    let retriedCount = 0;

    for (const type of types) {
      const failedKey = `failed_notifications:${type}`;
      const failedNotifications = await cache.get(failedKey) || [];

      for (const failed of failedNotifications) {
        if (failed.retryCount < 3) {
          try {
            if (type === 'email') {
              await sendEmail(
                failed.data.recipient,
                failed.data.subject,
                failed.data.template,
                failed.data.variables || {}
              );
            }

            // Remove from failed list on success
            const updatedFailed = failedNotifications.filter(f => f !== failed);
            await cache.set(failedKey, updatedFailed, 24 * 60 * 60);
            retriedCount++;

          } catch (retryError) {
            // Increment retry count
            failed.retryCount++;
            failed.lastRetryAt = new Date();
            logger.warn('Notification retry failed', retryError, { 
              type, 
              retryCount: failed.retryCount 
            });
          }
        }
      }

      // Clean up notifications that have exceeded max retries
      const validFailed = failedNotifications.filter(f => f.retryCount < 3);
      await cache.set(failedKey, validFailed, 24 * 60 * 60);
    }

    logger.info('Notification retry completed', { retriedCount });
    return retriedCount;

  } catch (error) {
    logger.error('Failed to retry notifications', error);
    return 0;
  }
};

/**
 * Send digest email (daily/weekly summary)
 */
const sendDigestEmail = async (userId, period = 'daily') => {
  try {
    const user = await User.findById(userId).select('email firstName lastName profile.preferences');
    
    if (!user || !user.profile?.preferences?.notifications?.email) {
      return { skipped: true, reason: 'user_preference' };
    }

    // Get user's tasks and activities for the period
    const dateRange = period === 'daily' 
      ? { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      : { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) };

    // This would typically query the database for user's activity
    const digestData = {
      period,
      tasksCompleted: 0, // Would be fetched from database
      tasksCreated: 0,
      commentsReceived: 0,
      upcomingDeadlines: []
    };

    // Only send if there's activity
    if (digestData.tasksCompleted === 0 && digestData.tasksCreated === 0 && 
        digestData.commentsReceived === 0 && digestData.upcomingDeadlines.length === 0) {
      return { skipped: true, reason: 'no_activity' };
    }

    return sendEmail(
      user.email,
      `Your ${period} task summary`,
      'digest',
      {
        firstName: user.firstName,
        period,
        ...digestData
      }
    );

  } catch (error) {
    logger.error('Failed to send digest email', error, { userId, period });
    throw error;
  }
};

/**
 * Send bulk notifications to multiple users
 */
const sendBulkNotifications = async (userIds, type, data) => {
  try {
    const notifications = userIds.map(userId => 
      sendRealTimeNotification(userId, type, data)
    );

    const results = await Promise.allSettled(notifications);
    
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    logger.info('Bulk notifications sent', {
      total: userIds.length,
      successful,
      failed,
      type
    });

    return { successful, failed, total: userIds.length };

  } catch (error) {
    logger.error('Failed to send bulk notifications', error);
    throw error;
  }
};

/**
 * Schedule notification for later delivery
 */
const scheduleNotification = async (userId, type, data, deliveryTime) => {
  try {
    const scheduledNotification = {
      id: require('uuid').v4(),
      userId,
      type,
      data,
      deliveryTime,
      scheduled: true,
      createdAt: new Date()
    };

    // Store in scheduled notifications list
    const scheduledKey = 'scheduled_notifications';
    const scheduled = await cache.get(scheduledKey) || [];
    scheduled.push(scheduledNotification);
    
    // Sort by delivery time
    scheduled.sort((a, b) => new Date(a.deliveryTime) - new Date(b.deliveryTime));
    
    // Store with long TTL
    await cache.set(scheduledKey, scheduled, 30 * 24 * 60 * 60); // 30 days

    logger.info('Notification scheduled', {
      userId,
      type,
      deliveryTime,
      notificationId: scheduledNotification.id
    });

    return scheduledNotification.id;

  } catch (error) {
    logger.error('Failed to schedule notification', error);
    throw error;
  }
};

/**
 * Process scheduled notifications
 */
const processScheduledNotifications = async () => {
  try {
    const scheduledKey = 'scheduled_notifications';
    const scheduled = await cache.get(scheduledKey) || [];
    const now = new Date();
    
    let processedCount = 0;
    const remaining = [];

    for (const notification of scheduled) {
      if (new Date(notification.deliveryTime) <= now) {
        try {
          if (notification.type.includes('email')) {
            await sendEmail(
              notification.userId,
              notification.data.subject,
              notification.data.template,
              notification.data.variables
            );
          } else {
            await sendRealTimeNotification(
              notification.userId,
              notification.type,
              notification.data
            );
          }
          processedCount++;
        } catch (error) {
          logger.error('Failed to process scheduled notification', error, {
            notificationId: notification.id
          });
          // Keep in scheduled list for retry
          remaining.push(notification);
        }
      } else {
        remaining.push(notification);
      }
    }

    // Update scheduled notifications list
    await cache.set(scheduledKey, remaining, 30 * 24 * 60 * 60);

    if (processedCount > 0) {
      logger.info('Scheduled notifications processed', { processedCount });
    }

    return processedCount;

  } catch (error) {
    logger.error('Failed to process scheduled notifications', error);
    return 0;
  }
};

/**
 * Initialize notification service
 */
const initializeNotificationService = () => {
  try {
    // Initialize email transporter
    initializeEmailTransporter();

    // Set up periodic tasks
    if (!config.isTest()) {
      // Process scheduled notifications every minute
      setInterval(processScheduledNotifications, 60 * 1000);

      // Retry failed notifications every 30 minutes
      setInterval(retryFailedNotifications, 30 * 60 * 1000);

      // Send daily digests at 9 AM
      const now = new Date();
      const nextNineAM = new Date(now);
      nextNineAM.setHours(9, 0, 0, 0);
      if (nextNineAM <= now) {
        nextNineAM.setDate(nextNineAM.getDate() + 1);
      }

      setTimeout(() => {
        // Send daily digests
        setInterval(async () => {
          try {
            // Get all users who want daily digests
            const users = await User.find({
              'profile.preferences.notifications.email': true,
              'profile.preferences.notifications.dailyDigest': true,
              isActive: true
            }).select('_id');

            for (const user of users) {
              await sendDigestEmail(user._id, 'daily');
            }
          } catch (error) {
            logger.error('Failed to send daily digests', error);
          }
        }, 24 * 60 * 60 * 1000); // Every 24 hours
      }, nextNineAM - now);
    }

    logger.info('✅ Notification service initialized');

  } catch (error) {
    logger.error('Failed to initialize notification service', error);
    throw error;
  }
};

module.exports = {
  // Core functions
  sendEmail,
  sendRealTimeNotification,
  getUserNotifications,
  markNotificationRead,
  deleteNotification,
  
  // Specific notification types
  sendEmailVerification,
  sendPasswordReset,
  sendWelcomeEmail,
  notifyTaskAssignment,
  notifyTaskUpdate,
  notifyTaskCompletion,
  notifyStatusChange,
  notifyHighPriorityTask,
  notifyTaskDeletion,
  
  // Advanced features
  sendDigestEmail,
  sendBulkNotifications,
  scheduleNotification,
  processScheduledNotifications,
  retryFailedNotifications,
  
  // Analytics and management
  getNotificationStats,
  
  // Initialization
  initializeNotificationService
};