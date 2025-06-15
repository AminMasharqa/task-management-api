/**
 * Authentication Routes
 * User authentication, registration, and token management endpoints
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../middleware/auth.middleware');
const validationMiddleware = require('../middleware/validation.middleware');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Stricter rate limiting for sensitive auth endpoints
 */
const strictAuthLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    success: false,
    message: 'Too many authentication attempts. Please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  onLimitReached: (req) => {
    logger.security('Auth rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path
    });
  }
});

/**
 * Password reset rate limiting
 */
const passwordResetLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset attempts per hour
  message: {
    success: false,
    message: 'Too many password reset requests. Please try again later.',
    retryAfter: '1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post(
  '/register',
  strictAuthLimit,
  validationMiddleware.validateRegister(),
  authController.register
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Authenticate user and return tokens
 * @access  Public
 */
router.post(
  '/login',
  strictAuthLimit,
  validationMiddleware.validateLogin(),
  authController.login
);

/**
 * @route   POST /api/v1/auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public
 */
router.post(
  '/refresh',
  validationMiddleware.validateRefreshToken(),
  authController.refreshToken
);

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout user and invalidate tokens
 * @access  Private
 */
router.post(
  '/logout',
  authMiddleware.authenticate(),
  authController.logout
);

/**
 * @route   POST /api/v1/auth/logout-all
 * @desc    Logout user from all devices
 * @access  Private
 */
router.post(
  '/logout-all',
  authMiddleware.authenticate(),
  authController.logoutAll
);

/**
 * @route   GET /api/v1/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get(
  '/me',
  authMiddleware.authenticate(),
  authController.getCurrentUser
);

/**
 * @route   PUT /api/v1/auth/me
 * @desc    Update current user profile
 * @access  Private
 */
router.put(
  '/me',
  authMiddleware.authenticate(),
  validationMiddleware.validateUpdateProfile(),
  authController.updateProfile
);

/**
 * @route   POST /api/v1/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post(
  '/change-password',
  authMiddleware.authenticate(),
  strictAuthLimit,
  validationMiddleware.validateChangePassword(),
  authController.changePassword
);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Request password reset email
 * @access  Public
 */
router.post(
  '/forgot-password',
  passwordResetLimit,
  validationMiddleware.validateForgotPassword(),
  authController.forgotPassword
);

/**
 * @route   POST /api/v1/auth/reset-password
 * @desc    Reset password using reset token
 * @access  Public
 */
router.post(
  '/reset-password',
  strictAuthLimit,
  validationMiddleware.validateResetPassword(),
  authController.resetPassword
);

/**
 * @route   POST /api/v1/auth/verify-email
 * @desc    Verify email address using verification token
 * @access  Public
 */
router.post(
  '/verify-email',
  validationMiddleware.validateEmailVerification(),
  authController.verifyEmail
);

/**
 * @route   POST /api/v1/auth/resend-verification
 * @desc    Resend email verification
 * @access  Private
 */
router.post(
  '/resend-verification',
  authMiddleware.authenticate(),
  passwordResetLimit, // Reuse rate limit for email sending
  authController.resendVerification
);

/**
 * @route   GET /api/v1/auth/sessions
 * @desc    Get user's active sessions
 * @access  Private
 */
router.get(
  '/sessions',
  authMiddleware.authenticate(),
  authController.getSessions
);

/**
 * @route   DELETE /api/v1/auth/sessions/:sessionId
 * @desc    Revoke specific session
 * @access  Private
 */
router.delete(
  '/sessions/:sessionId',
  authMiddleware.authenticate(),
  validationMiddleware.validateSessionId(),
  authController.revokeSession
);

/**
 * @route   POST /api/v1/auth/enable-2fa
 * @desc    Enable two-factor authentication
 * @access  Private
 */
router.post(
  '/enable-2fa',
  authMiddleware.authenticate(),
  authController.enableTwoFactor
);

/**
 * @route   POST /api/v1/auth/verify-2fa
 * @desc    Verify two-factor authentication code
 * @access  Private
 */
router.post(
  '/verify-2fa',
  authMiddleware.authenticate(),
  validationMiddleware.validateTwoFactorCode(),
  authController.verifyTwoFactor
);

/**
 * @route   POST /api/v1/auth/disable-2fa
 * @desc    Disable two-factor authentication
 * @access  Private
 */
router.post(
  '/disable-2fa',
  authMiddleware.authenticate(),
  strictAuthLimit,
  validationMiddleware.validateDisableTwoFactor(),
  authController.disableTwoFactor
);

/**
 * @route   GET /api/v1/auth/security-log
 * @desc    Get user's security activity log
 * @access  Private
 */
router.get(
  '/security-log',
  authMiddleware.authenticate(),
  authController.getSecurityLog
);

/**
 * OAuth Routes (External Authentication)
 */

/**
 * @route   GET /api/v1/auth/google
 * @desc    Initiate Google OAuth flow
 * @access  Public
 */
router.get('/google', authController.initiateGoogleAuth);

/**
 * @route   GET /api/v1/auth/google/callback
 * @desc    Handle Google OAuth callback
 * @access  Public
 */
router.get('/google/callback', authController.handleGoogleCallback);

/**
 * @route   GET /api/v1/auth/github
 * @desc    Initiate GitHub OAuth flow
 * @access  Public
 */
router.get('/github', authController.initiateGithubAuth);

/**
 * @route   GET /api/v1/auth/github/callback
 * @desc    Handle GitHub OAuth callback
 * @access  Public
 */
router.get('/github/callback', authController.handleGithubCallback);

/**
 * Development and Testing Routes
 */
if (process.env.NODE_ENV === 'development') {
  /**
   * @route   POST /api/v1/auth/dev/create-test-user
   * @desc    Create test user for development
   * @access  Development only
   */
  router.post(
    '/dev/create-test-user',
    validationMiddleware.validateCreateTestUser(),
    authController.createTestUser
  );

  /**
   * @route   POST /api/v1/auth/dev/generate-tokens
   * @desc    Generate tokens for testing
   * @access  Development only
   */
  router.post(
    '/dev/generate-tokens',
    validationMiddleware.validateGenerateTokens(),
    authController.generateTestTokens
  );

  logger.info('🔧 Auth development routes enabled');
}

/**
 * Route documentation endpoint
 */
router.get('/', (req, res) => {
  res.json({
    name: 'Authentication API',
    version: '1.0.0',
    description: 'User authentication and authorization endpoints',
    endpoints: {
      public: [
        'POST /register - User registration',
        'POST /login - User authentication',
        'POST /refresh - Refresh access token',
        'POST /forgot-password - Request password reset',
        'POST /reset-password - Reset password with token',
        'POST /verify-email - Verify email address',
        'GET /google - Google OAuth login',
        'GET /github - GitHub OAuth login'
      ],
      private: [
        'POST /logout - Logout current session',
        'POST /logout-all - Logout all sessions',
        'GET /me - Get current user',
        'PUT /me - Update user profile',
        'POST /change-password - Change password',
        'POST /resend-verification - Resend email verification',
        'GET /sessions - Get active sessions',
        'DELETE /sessions/:id - Revoke session',
        'POST /enable-2fa - Enable 2FA',
        'POST /verify-2fa - Verify 2FA code',
        'POST /disable-2fa - Disable 2FA',
        'GET /security-log - Security activity log'
      ]
    },
    security: {
      rateLimiting: 'Strict limits on sensitive endpoints',
      tokenTypes: 'JWT access + refresh tokens',
      sessionManagement: 'Multi-device session tracking',
      twoFactor: 'TOTP-based 2FA support',
      oauth: 'Google and GitHub integration'
    }
  });
});

module.exports = router;