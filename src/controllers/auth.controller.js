/**
 * Authentication Controller
 * Handles user authentication, registration, and security operations
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const User = require('../models/User');
const authService = require('../services/auth.service');
const notificationService = require('../services/notification.service');
const { cache } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * @desc    Register a new user
 * @route   POST /api/v1/auth/register
 * @access  Public
 */
const register = async (req, res, next) => {
  try {
    const { email, password, firstName, lastName, username } = req.body;

    logger.info('User registration attempt', { email, username });

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      logger.security('Registration attempted with existing credentials', {
        email,
        username,
        existingField: existingUser.email === email ? 'email' : 'username',
        ip: req.ip
      });

      return res.status(400).json({
        success: false,
        message: 'User already exists with this email or username',
        field: existingUser.email === email ? 'email' : 'username'
      });
    }

    // Hash password
    const saltRounds = config.security.saltRounds;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate email verification token
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      username,
      emailVerificationToken,
      emailVerificationExpires,
      profile: {
        avatar: null,
        bio: '',
        preferences: {
          notifications: {
            email: true,
            push: true,
            taskUpdates: true,
            comments: true
          },
          privacy: {
            profileVisible: true,
            activityVisible: false
          }
        }
      }
    });

    await user.save();

    // Generate tokens
    const { accessToken, refreshToken } = await authService.generateTokenPair(user);

    // Create session
    const sessionId = uuidv4();
    await authService.createSession(user._id, sessionId, req);

    // Send verification email
    try {
      await notificationService.sendEmailVerification(user, emailVerificationToken);
      logger.info('Verification email sent', { userId: user._id, email });
    } catch (emailError) {
      logger.error('Failed to send verification email', emailError, { userId: user._id });
      // Don't fail registration if email fails
    }

    // Log successful registration
    logger.business('User registered successfully', {
      userId: user._id,
      email,
      username,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please check your email to verify your account.',
      data: {
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          emailVerified: user.emailVerified,
          role: user.role,
          createdAt: user.createdAt
        },
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: config.jwt.expiresIn
        },
        sessionId
      }
    });

  } catch (error) {
    logger.error('Registration error', error, { email: req.body?.email });
    next(error);
  }
};

/**
 * @desc    Authenticate user and return tokens
 * @route   POST /api/v1/auth/login
 * @access  Public
 */
const login = async (req, res, next) => {
  try {
    const { email, password, rememberMe = false } = req.body;

    logger.info('Login attempt', { email, ip: req.ip });

    // Find user by email or username
    const user = await User.findOne({
      $or: [{ email }, { username: email }]
    }).select('+password +loginAttempts +lockUntil');

    if (!user) {
      logger.security('Login attempted with non-existent user', { email, ip: req.ip });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 60000); // minutes
      
      logger.security('Login attempted on locked account', {
        userId: user._id,
        email,
        lockTimeRemaining,
        ip: req.ip
      });

      return res.status(423).json({
        success: false,
        message: `Account is locked. Try again in ${lockTimeRemaining} minutes.`,
        lockTimeRemaining
      });
    }

    // Check if account is deactivated
    if (!user.isActive) {
      logger.security('Login attempted on deactivated account', {
        userId: user._id,
        email,
        ip: req.ip
      });

      return res.status(403).json({
        success: false,
        message: 'Account is deactivated. Please contact support.'
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Increment failed login attempts
      await user.incLoginAttempts();
      
      logger.security('Invalid password attempt', {
        userId: user._id,
        email,
        attempts: user.loginAttempts + 1,
        ip: req.ip
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Reset login attempts on successful login
    if (user.loginAttempts > 0) {
      await user.resetLoginAttempts();
    }

    // Check 2FA if enabled
    if (user.twoFactorEnabled) {
      // Generate temporary token for 2FA verification
      const tempToken = await authService.generateTempToken(user._id, '2fa-pending');
      
      logger.info('2FA verification required', { userId: user._id });

      return res.status(200).json({
        success: true,
        message: '2FA verification required',
        requiresTwoFactor: true,
        tempToken
      });
    }

    // Generate tokens
    const tokenExpiry = rememberMe ? '30d' : config.jwt.expiresIn;
    const { accessToken, refreshToken } = await authService.generateTokenPair(user, tokenExpiry);

    // Create session
    const sessionId = uuidv4();
    await authService.createSession(user._id, sessionId, req);

    // Update last login
    user.lastLoginAt = new Date();
    user.lastLoginIP = req.ip;
    await user.save();

    // Cache user data
    await cache.set(`user:${user._id}`, {
      id: user._id,
      email: user.email,
      username: user.username,
      role: user.role,
      emailVerified: user.emailVerified
    }, 3600); // 1 hour

    logger.business('User logged in successfully', {
      userId: user._id,
      email,
      sessionId,
      rememberMe,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          emailVerified: user.emailVerified,
          role: user.role,
          lastLoginAt: user.lastLoginAt
        },
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: tokenExpiry
        },
        sessionId
      }
    });

  } catch (error) {
    logger.error('Login error', error, { email: req.body?.email });
    next(error);
  }
};

/**
 * @desc    Refresh access token
 * @route   POST /api/v1/auth/refresh
 * @access  Public
 */
const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken: token } = req.body;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(token, config.jwt.refreshSecret);
    
    // Check if token is blacklisted
    const isBlacklisted = await cache.exists(`blacklist:${token}`);
    if (isBlacklisted) {
      logger.security('Blacklisted refresh token used', {
        userId: decoded.userId,
        ip: req.ip
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Find user
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Generate new token pair
    const { accessToken, refreshToken: newRefreshToken } = await authService.generateTokenPair(user);

    // Blacklist old refresh token
    await cache.set(`blacklist:${token}`, true, 7 * 24 * 3600); // 7 days

    logger.info('Token refreshed successfully', { userId: user._id });

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        tokens: {
          accessToken,
          refreshToken: newRefreshToken,
          expiresIn: config.jwt.expiresIn
        }
      }
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token'
      });
    }

    logger.error('Token refresh error', error);
    next(error);
  }
};

/**
 * @desc    Logout user
 * @route   POST /api/v1/auth/logout
 * @access  Private
 */
const logout = async (req, res, next) => {
  try {
    const { user } = req;
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    // Blacklist current access token
    if (token) {
      const decoded = jwt.decode(token);
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await cache.set(`blacklist:${token}`, true, ttl);
      }
    }

    // Remove session
    const sessionId = req.headers['x-session-id'];
    if (sessionId) {
      await authService.removeSession(user.id, sessionId);
    }

    // Clear user cache
    await cache.del(`user:${user.id}`);

    logger.business('User logged out', {
      userId: user.id,
      sessionId,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    logger.error('Logout error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Logout user from all devices
 * @route   POST /api/v1/auth/logout-all
 * @access  Private
 */
const logoutAll = async (req, res, next) => {
  try {
    const { user } = req;

    // Remove all user sessions
    await authService.removeAllSessions(user.id);

    // Clear user cache
    await cache.del(`user:${user.id}`);

    // Increment token version to invalidate all tokens
    await User.findByIdAndUpdate(user.id, {
      $inc: { tokenVersion: 1 }
    });

    logger.business('User logged out from all devices', {
      userId: user.id,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'Logged out from all devices successfully'
    });

  } catch (error) {
    logger.error('Logout all error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get current user profile
 * @route   GET /api/v1/auth/me
 * @access  Private
 */
const getCurrentUser = async (req, res, next) => {
  try {
    const { user } = req;

    // Get full user data
    const userData = await User.findById(user.id)
      .populate('teams', 'name slug')
      .lean();

    if (!userData) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user: {
          id: userData._id,
          email: userData.email,
          username: userData.username,
          firstName: userData.firstName,
          lastName: userData.lastName,
          emailVerified: userData.emailVerified,
          twoFactorEnabled: userData.twoFactorEnabled,
          role: userData.role,
          profile: userData.profile,
          teams: userData.teams,
          createdAt: userData.createdAt,
          lastLoginAt: userData.lastLoginAt
        }
      }
    });

  } catch (error) {
    logger.error('Get current user error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Update user profile
 * @route   PUT /api/v1/auth/me
 * @access  Private
 */
const updateProfile = async (req, res, next) => {
  try {
    const { user } = req;
    const updateData = req.body;

    // Remove sensitive fields that can't be updated via this endpoint
    delete updateData.password;
    delete updateData.email;
    delete updateData.role;
    delete updateData.emailVerified;

    const updatedUser = await User.findByIdAndUpdate(
      user.id,
      { $set: updateData },
      { new: true, runValidators: true }
    ).lean();

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Clear user cache
    await cache.del(`user:${user.id}`);

    logger.business('User profile updated', {
      userId: user.id,
      updatedFields: Object.keys(updateData)
    });

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: {
          id: updatedUser._id,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          username: updatedUser.username,
          profile: updatedUser.profile
        }
      }
    });

  } catch (error) {
    logger.error('Update profile error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Change user password
 * @route   POST /api/v1/auth/change-password
 * @access  Private
 */
const changePassword = async (req, res, next) => {
  try {
    const { user } = req;
    const { currentPassword, newPassword } = req.body;

    // Get user with password
    const userData = await User.findById(user.id).select('+password');

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, userData.password);
    if (!isCurrentPasswordValid) {
      logger.security('Invalid current password in change password attempt', {
        userId: user.id,
        ip: req.ip
      });

      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, config.security.saltRounds);

    // Update password and increment token version
    await User.findByIdAndUpdate(user.id, {
      password: hashedNewPassword,
      $inc: { tokenVersion: 1 },
      passwordChangedAt: new Date()
    });

    // Remove all sessions except current
    const currentSessionId = req.headers['x-session-id'];
    await authService.removeAllSessionsExcept(user.id, currentSessionId);

    logger.business('Password changed successfully', {
      userId: user.id,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    logger.error('Change password error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Request password reset
 * @route   POST /api/v1/auth/forgot-password
 * @access  Public
 */
const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    // Always return success to prevent email enumeration
    const successResponse = {
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.'
    };

    if (!user) {
      logger.security('Password reset requested for non-existent email', {
        email,
        ip: req.ip
      });
      return res.status(200).json(successResponse);
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Save reset token
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetTokenExpires;
    await user.save();

    // Send reset email
    try {
      await notificationService.sendPasswordReset(user, resetToken);
      logger.info('Password reset email sent', { userId: user._id });
    } catch (emailError) {
      logger.error('Failed to send password reset email', emailError, { userId: user._id });
      // Clear reset token if email fails
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      return res.status(500).json({
        success: false,
        message: 'Failed to send password reset email. Please try again.'
      });
    }

    res.status(200).json(successResponse);

  } catch (error) {
    logger.error('Forgot password error', error);
    next(error);
  }
};

/**
 * @desc    Reset password using reset token
 * @route   POST /api/v1/auth/reset-password
 * @access  Public
 */
const resetPassword = async (req, res, next) => {
  try {
    const { token, password } = req.body;

    // Find user with valid reset token
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      logger.security('Invalid or expired password reset token used', {
        token: token.substring(0, 8) + '...',
        ip: req.ip
      });

      return res.status(400).json({
        success: false,
        message: 'Invalid or expired password reset token'
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, config.security.saltRounds);

    // Update user
    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = new Date();
    user.tokenVersion += 1; // Invalidate all existing tokens
    await user.save();

    // Remove all user sessions
    await authService.removeAllSessions(user._id);

    logger.business('Password reset successfully', {
      userId: user._id,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'Password reset successfully. Please log in with your new password.'
    });

  } catch (error) {
    logger.error('Reset password error', error);
    next(error);
  }
};

/**
 * @desc    Verify email address
 * @route   POST /api/v1/auth/verify-email
 * @access  Public
 */
const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.body;

    // Find user with valid verification token
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    // Update user
    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    logger.business('Email verified successfully', { userId: user._id });

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });

  } catch (error) {
    logger.error('Email verification error', error);
    next(error);
  }
};

/**
 * @desc    Resend email verification
 * @route   POST /api/v1/auth/resend-verification
 * @access  Private
 */
const resendVerification = async (req, res, next) => {
  try {
    const { user } = req;

    const userData = await User.findById(user.id);

    if (userData.emailVerified) {
      return res.status(400).json({
        success: false,
        message: 'Email is already verified'
      });
    }

    // Generate new verification token
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    userData.emailVerificationToken = emailVerificationToken;
    userData.emailVerificationExpires = emailVerificationExpires;
    await userData.save();

    // Send verification email
    await notificationService.sendEmailVerification(userData, emailVerificationToken);

    logger.info('Verification email resent', { userId: user.id });

    res.status(200).json({
      success: true,
      message: 'Verification email sent successfully'
    });

  } catch (error) {
    logger.error('Resend verification error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Get user sessions
 * @route   GET /api/v1/auth/sessions
 * @access  Private
 */
const getSessions = async (req, res, next) => {
  try {
    const { user } = req;

    const sessions = await authService.getUserSessions(user.id);

    res.status(200).json({
      success: true,
      data: { sessions }
    });

  } catch (error) {
    logger.error('Get sessions error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * @desc    Revoke specific session
 * @route   DELETE /api/v1/auth/sessions/:sessionId
 * @access  Private
 */
const revokeSession = async (req, res, next) => {
  try {
    const { user } = req;
    const { sessionId } = req.params;

    await authService.removeSession(user.id, sessionId);

    logger.business('Session revoked', {
      userId: user.id,
      sessionId,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'Session revoked successfully'
    });

  } catch (error) {
    logger.error('Revoke session error', error, { userId: req.user?.id });
    next(error);
  }
};

/**
 * Development helper functions
 */
const createTestUser = async (req, res, next) => {
  if (config.nodeEnv !== 'development') {
    return res.status(404).json({ success: false, message: 'Not found' });
  }

  try {
    const { email = 'test@example.com', password = 'Test123!', role = 'user' } = req.body;

    // Delete existing test user
    await User.deleteOne({ email });

    // Create test user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      firstName: 'Test',
      lastName: 'User',
      username: `test_${Date.now()}`,
      emailVerified: true,
      role
    });

    await user.save();

    res.status(201).json({
      success: true,
      message: 'Test user created',
      data: { user: { id: user._id, email, role } }
    });

  } catch (error) {
    next(error);
  }
};

const generateTestTokens = async (req, res, next) => {
  if (config.nodeEnv !== 'development') {
    return res.status(404).json({ success: false, message: 'Not found' });
  }

  try {
    const { userId } = req.body;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const { accessToken, refreshToken } = await authService.generateTokenPair(user);

    res.status(200).json({
      success: true,
      data: { accessToken, refreshToken }
    });

  } catch (error) {
    next(error);
  }
};

// Placeholder functions for advanced features
const enableTwoFactor = async (req, res) => {
  res.status(501).json({ success: false, message: 'Two-factor authentication not yet implemented' });
};

const verifyTwoFactor = async (req, res) => {
  res.status(501).json({ success: false, message: 'Two-factor authentication not yet implemented' });
};

const disableTwoFactor = async (req, res) => {
  res.status(501).json({ success: false, message: 'Two-factor authentication not yet implemented' });
};

const getSecurityLog = async (req, res) => {
  res.status(501).json({ success: false, message: 'Security log not yet implemented' });
};

const initiateGoogleAuth = async (req, res) => {
  res.status(501).json({ success: false, message: 'Google OAuth not yet implemented' });
};

const handleGoogleCallback = async (req, res) => {
  res.status(501).json({ success: false, message: 'Google OAuth not yet implemented' });
};

const initiateGithubAuth = async (req, res) => {
  res.status(501).json({ success: false, message: 'GitHub OAuth not yet implemented' });
};

const handleGithubCallback = async (req, res) => {
  res.status(501).json({ success: false, message: 'GitHub OAuth not yet implemented' });
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  logoutAll,
  getCurrentUser,
  updateProfile,
  changePassword,
  forgotPassword,
  resetPassword,
  verifyEmail,
  resendVerification,
  getSessions,
  revokeSession,
  enableTwoFactor,
  verifyTwoFactor,
  disableTwoFactor,
  getSecurityLog,
  initiateGoogleAuth,
  handleGoogleCallback,
  initiateGithubAuth,
  handleGithubCallback,
  createTestUser,
  generateTestTokens
};