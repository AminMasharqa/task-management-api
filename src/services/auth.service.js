/**
 * Authentication Service
 * JWT token management, session handling, and security features
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const { cache } = require('../config/redis');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Generate JWT token pair (access + refresh)
 */
const generateTokenPair = async (user, accessTokenExpiry = null) => {
  try {
    const userId = user._id || user.id;
    const tokenVersion = user.tokenVersion || 0;
    
    // Access token payload
    const accessPayload = {
      userId,
      email: user.email,
      username: user.username,
      role: user.role,
      emailVerified: user.emailVerified,
      tokenVersion,
      type: 'access'
    };

    // Refresh token payload
    const refreshPayload = {
      userId,
      tokenVersion,
      type: 'refresh'
    };

    // Generate tokens
    const accessToken = jwt.sign(
      accessPayload,
      config.jwt.secret,
      {
        expiresIn: accessTokenExpiry || config.jwt.expiresIn,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience
      }
    );

    const refreshToken = jwt.sign(
      refreshPayload,
      config.jwt.refreshSecret,
      {
        expiresIn: config.jwt.refreshExpiresIn,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience
      }
    );

    logger.debug('Token pair generated', { 
      userId,
      accessTokenExpiry: accessTokenExpiry || config.jwt.expiresIn 
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: accessTokenExpiry || config.jwt.expiresIn
    };

  } catch (error) {
    logger.error('Failed to generate token pair', error, { userId: user._id });
    throw new Error('Token generation failed');
  }
};

/**
 * Verify JWT token
 */
const verifyToken = async (token, type = 'access') => {
  try {
    const secret = type === 'access' ? config.jwt.secret : config.jwt.refreshSecret;
    
    const decoded = jwt.verify(token, secret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience
    });

    // Validate token type
    if (decoded.type !== type) {
      throw new Error(`Invalid token type. Expected ${type}, got ${decoded.type}`);
    }

    // Check if token is blacklisted
    const isBlacklisted = await cache.exists(`blacklist:${token}`);
    if (isBlacklisted) {
      throw new Error('Token has been revoked');
    }

    // For access tokens, verify user still exists and token version matches
    if (type === 'access') {
      const user = await User.findById(decoded.userId).select('tokenVersion isActive emailVerified role');
      
      if (!user) {
        throw new Error('User not found');
      }

      if (!user.isActive) {
        throw new Error('User account is deactivated');
      }

      if (user.tokenVersion !== decoded.tokenVersion) {
        throw new Error('Token version mismatch - please login again');
      }

      // Return user data with token payload
      return {
        ...decoded,
        user: {
          id: user._id,
          isActive: user.isActive,
          emailVerified: user.emailVerified,
          role: user.role,
          currentTokenVersion: user.tokenVersion
        }
      };
    }

    return decoded;

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    } else if (error.name === 'TokenExpiredError') {
      throw new Error('Token has expired');
    } else {
      throw error;
    }
  }
};

/**
 * Generate temporary token for specific purposes (2FA, password reset, etc.)
 */
const generateTempToken = async (userId, purpose, expiresIn = '15m') => {
  try {
    const payload = {
      userId,
      purpose,
      type: 'temporary',
      tokenId: uuidv4()
    };

    const token = jwt.sign(
      payload,
      config.jwt.secret,
      {
        expiresIn,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience
      }
    );

    // Store temp token in cache for validation
    const decoded = jwt.decode(token);
    const ttl = decoded.exp - Math.floor(Date.now() / 1000);
    await cache.set(`temp_token:${payload.tokenId}`, {
      userId,
      purpose,
      createdAt: new Date()
    }, ttl);

    logger.debug('Temporary token generated', { userId, purpose, expiresIn });

    return token;

  } catch (error) {
    logger.error('Failed to generate temporary token', error, { userId, purpose });
    throw new Error('Temporary token generation failed');
  }
};

/**
 * Verify temporary token
 */
const verifyTempToken = async (token, expectedPurpose) => {
  try {
    const decoded = jwt.verify(token, config.jwt.secret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience
    });

    if (decoded.type !== 'temporary') {
      throw new Error('Invalid token type');
    }

    if (decoded.purpose !== expectedPurpose) {
      throw new Error(`Invalid token purpose. Expected ${expectedPurpose}, got ${decoded.purpose}`);
    }

    // Check if temp token exists in cache
    const tokenData = await cache.get(`temp_token:${decoded.tokenId}`);
    if (!tokenData) {
      throw new Error('Temporary token not found or expired');
    }

    // Remove token from cache (single use)
    await cache.del(`temp_token:${decoded.tokenId}`);

    return decoded;

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid temporary token');
    } else if (error.name === 'TokenExpiredError') {
      throw new Error('Temporary token has expired');
    } else {
      throw error;
    }
  }
};

/**
 * Blacklist token (for logout)
 */
const blacklistToken = async (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded) {
      return false;
    }

    const ttl = decoded.exp - Math.floor(Date.now() / 1000);
    if (ttl > 0) {
      await cache.set(`blacklist:${token}`, true, ttl);
      logger.debug('Token blacklisted', { tokenId: decoded.jti || 'unknown' });
    }

    return true;

  } catch (error) {
    logger.error('Failed to blacklist token', error);
    return false;
  }
};

/**
 * Create user session
 */
const createSession = async (userId, sessionId, req) => {
  try {
    const sessionData = {
      sessionId,
      userId,
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.get('User-Agent'),
      createdAt: new Date(),
      lastAccessedAt: new Date(),
      isActive: true
    };

    // Store session in Redis with 7 day TTL
    const sessionKey = `session:${userId}:${sessionId}`;
    await cache.set(sessionKey, sessionData, 7 * 24 * 60 * 60); // 7 days

    // Add to user's session list
    const userSessionsKey = `user_sessions:${userId}`;
    const existingSessions = await cache.get(userSessionsKey) || [];
    
    // Remove old sessions if more than 10 active sessions
    if (existingSessions.length >= 10) {
      const oldestSession = existingSessions.shift();
      await cache.del(`session:${userId}:${oldestSession.sessionId}`);
    }

    existingSessions.push({
      sessionId,
      createdAt: sessionData.createdAt,
      ip: sessionData.ip,
      userAgent: sessionData.userAgent
    });

    await cache.set(userSessionsKey, existingSessions, 7 * 24 * 60 * 60);

    logger.info('Session created', {
      userId,
      sessionId,
      ip: sessionData.ip,
      userAgent: sessionData.userAgent
    });

    return sessionData;

  } catch (error) {
    logger.error('Failed to create session', error, { userId, sessionId });
    throw new Error('Session creation failed');
  }
};

/**
 * Update session last accessed time
 */
const updateSessionAccess = async (userId, sessionId) => {
  try {
    const sessionKey = `session:${userId}:${sessionId}`;
    const session = await cache.get(sessionKey);

    if (session) {
      session.lastAccessedAt = new Date();
      await cache.set(sessionKey, session, 7 * 24 * 60 * 60);
    }

  } catch (error) {
    logger.error('Failed to update session access', error, { userId, sessionId });
    // Don't throw error as this is not critical
  }
};

/**
 * Get user sessions
 */
const getUserSessions = async (userId) => {
  try {
    const userSessionsKey = `user_sessions:${userId}`;
    const sessions = await cache.get(userSessionsKey) || [];

    // Get full session data for each session
    const fullSessions = await Promise.all(
      sessions.map(async (session) => {
        const sessionKey = `session:${userId}:${session.sessionId}`;
        const fullSession = await cache.get(sessionKey);
        return fullSession || session;
      })
    );

    // Filter out inactive sessions
    const activeSessions = fullSessions.filter(session => session && session.isActive !== false);

    return activeSessions.map(session => ({
      sessionId: session.sessionId,
      ip: session.ip,
      userAgent: session.userAgent,
      createdAt: session.createdAt,
      lastAccessedAt: session.lastAccessedAt,
      isCurrent: false // This would be determined by comparing with current session
    }));

  } catch (error) {
    logger.error('Failed to get user sessions', error, { userId });
    return [];
  }
};

/**
 * Remove specific session
 */
const removeSession = async (userId, sessionId) => {
  try {
    // Remove session data
    const sessionKey = `session:${userId}:${sessionId}`;
    await cache.del(sessionKey);

    // Remove from user sessions list
    const userSessionsKey = `user_sessions:${userId}`;
    const existingSessions = await cache.get(userSessionsKey) || [];
    const updatedSessions = existingSessions.filter(s => s.sessionId !== sessionId);
    
    if (updatedSessions.length > 0) {
      await cache.set(userSessionsKey, updatedSessions, 7 * 24 * 60 * 60);
    } else {
      await cache.del(userSessionsKey);
    }

    logger.info('Session removed', { userId, sessionId });

  } catch (error) {
    logger.error('Failed to remove session', error, { userId, sessionId });
    throw new Error('Session removal failed');
  }
};

/**
 * Remove all user sessions
 */
const removeAllSessions = async (userId) => {
  try {
    const userSessionsKey = `user_sessions:${userId}`;
    const sessions = await cache.get(userSessionsKey) || [];

    // Remove all session data
    const promises = sessions.map(session => 
      cache.del(`session:${userId}:${session.sessionId}`)
    );
    await Promise.all(promises);

    // Remove user sessions list
    await cache.del(userSessionsKey);

    logger.info('All sessions removed', { userId, count: sessions.length });

  } catch (error) {
    logger.error('Failed to remove all sessions', error, { userId });
    throw new Error('Session removal failed');
  }
};

/**
 * Remove all sessions except current
 */
const removeAllSessionsExcept = async (userId, currentSessionId) => {
  try {
    const userSessionsKey = `user_sessions:${userId}`;
    const sessions = await cache.get(userSessionsKey) || [];

    // Remove all sessions except current
    const promises = sessions
      .filter(session => session.sessionId !== currentSessionId)
      .map(session => cache.del(`session:${userId}:${session.sessionId}`));
    
    await Promise.all(promises);

    // Update user sessions list to keep only current session
    const currentSession = sessions.find(s => s.sessionId === currentSessionId);
    if (currentSession) {
      await cache.set(userSessionsKey, [currentSession], 7 * 24 * 60 * 60);
    } else {
      await cache.del(userSessionsKey);
    }

    logger.info('All sessions removed except current', { 
      userId, 
      currentSessionId,
      removedCount: sessions.length - 1 
    });

  } catch (error) {
    logger.error('Failed to remove sessions except current', error, { userId, currentSessionId });
    throw new Error('Session removal failed');
  }
};

/**
 * Validate session
 */
const validateSession = async (userId, sessionId) => {
  try {
    if (!sessionId) return false;

    const sessionKey = `session:${userId}:${sessionId}`;
    const session = await cache.get(sessionKey);

    if (!session || !session.isActive) {
      return false;
    }

    // Update last accessed time
    await updateSessionAccess(userId, sessionId);

    return true;

  } catch (error) {
    logger.error('Failed to validate session', error, { userId, sessionId });
    return false;
  }
};

/**
 * Generate secure random token
 */
const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate API key for service-to-service communication
 */
const generateApiKey = async (userId, name, permissions = []) => {
  try {
    const apiKey = `ak_${generateSecureToken(32)}`;
    const keyData = {
      userId,
      name,
      permissions,
      createdAt: new Date(),
      lastUsedAt: null,
      isActive: true
    };

    // Store API key data (no expiration for API keys)
    await cache.set(`api_key:${apiKey}`, keyData);

    // Add to user's API keys list
    const userApiKeysKey = `user_api_keys:${userId}`;
    const existingKeys = await cache.get(userApiKeysKey) || [];
    existingKeys.push({
      apiKey: apiKey.substring(0, 12) + '...', // Masked version for display
      name,
      permissions,
      createdAt: keyData.createdAt
    });
    await cache.set(userApiKeysKey, existingKeys);

    logger.info('API key generated', { userId, name, permissions });

    return { apiKey, ...keyData };

  } catch (error) {
    logger.error('Failed to generate API key', error, { userId, name });
    throw new Error('API key generation failed');
  }
};

/**
 * Validate API key
 */
const validateApiKey = async (apiKey) => {
  try {
    const keyData = await cache.get(`api_key:${apiKey}`);
    
    if (!keyData || !keyData.isActive) {
      return null;
    }

    // Update last used time
    keyData.lastUsedAt = new Date();
    await cache.set(`api_key:${apiKey}`, keyData);

    return keyData;

  } catch (error) {
    logger.error('Failed to validate API key', error);
    return null;
  }
};

/**
 * Revoke API key
 */
const revokeApiKey = async (apiKey) => {
  try {
    const keyData = await cache.get(`api_key:${apiKey}`);
    
    if (keyData) {
      keyData.isActive = false;
      keyData.revokedAt = new Date();
      await cache.set(`api_key:${apiKey}`, keyData);
      
      logger.info('API key revoked', { userId: keyData.userId });
    }

  } catch (error) {
    logger.error('Failed to revoke API key', error);
    throw new Error('API key revocation failed');
  }
};

/**
 * Clean up expired sessions and tokens
 */
const cleanupExpiredSessions = async () => {
  try {
    // This would typically be run as a scheduled job
    logger.info('Starting session cleanup job');

    // Get all user session keys
    const userSessionKeys = await cache.keys('user_sessions:*');
    let cleanedCount = 0;

    for (const userKey of userSessionKeys) {
      const sessions = await cache.get(userKey) || [];
      const activeSessions = [];

      for (const session of sessions) {
        const sessionKey = `session:${userKey.split(':')[1]}:${session.sessionId}`;
        const sessionData = await cache.get(sessionKey);
        
        if (sessionData && sessionData.isActive) {
          activeSessions.push(session);
        } else {
          cleanedCount++;
        }
      }

      if (activeSessions.length > 0) {
        await cache.set(userKey, activeSessions, 7 * 24 * 60 * 60);
      } else {
        await cache.del(userKey);
      }
    }

    logger.info('Session cleanup completed', { cleanedCount });
    return cleanedCount;

  } catch (error) {
    logger.error('Session cleanup failed', error);
    throw error;
  }
};

/**
 * Get authentication statistics
 */
const getAuthStats = async () => {
  try {
    const [
      activeSessionsCount,
      blacklistedTokensCount,
      apiKeysCount
    ] = await Promise.all([
      cache.keys('session:*').then(keys => keys.length),
      cache.keys('blacklist:*').then(keys => keys.length),
      cache.keys('api_key:*').then(keys => keys.length)
    ]);

    return {
      activeSessions: activeSessionsCount,
      blacklistedTokens: blacklistedTokensCount,
      apiKeys: apiKeysCount,
      timestamp: new Date()
    };

  } catch (error) {
    logger.error('Failed to get auth stats', error);
    return {
      activeSessions: 0,
      blacklistedTokens: 0,
      apiKeys: 0,
      timestamp: new Date(),
      error: 'Failed to retrieve statistics'
    };
  }
};

module.exports = {
  generateTokenPair,
  verifyToken,
  generateTempToken,
  verifyTempToken,
  blacklistToken,
  createSession,
  updateSessionAccess,
  getUserSessions,
  removeSession,
  removeAllSessions,
  removeAllSessionsExcept,
  validateSession,
  generateSecureToken,
  generateApiKey,
  validateApiKey,
  revokeApiKey,
  cleanupExpiredSessions,
  getAuthStats
};