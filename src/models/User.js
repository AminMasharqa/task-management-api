/**
 * User Model
 * MongoDB schema for user accounts with authentication and profile management
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config');

const { Schema } = mongoose;

/**
 * User preferences sub-schema
 */
const preferencesSchema = new Schema({
  notifications: {
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
    taskUpdates: { type: Boolean, default: true },
    comments: { type: Boolean, default: true },
    assignments: { type: Boolean, default: true },
    mentions: { type: Boolean, default: true }
  },
  privacy: {
    profileVisible: { type: Boolean, default: true },
    activityVisible: { type: Boolean, default: false },
    emailVisible: { type: Boolean, default: false }
  },
  ui: {
    theme: { 
      type: String, 
      enum: ['light', 'dark', 'auto'], 
      default: 'auto' 
    },
    language: { 
      type: String, 
      enum: ['en', 'es', 'fr', 'de', 'pt'], 
      default: 'en' 
    },
    timezone: { 
      type: String, 
      default: 'UTC' 
    },
    dateFormat: { 
      type: String, 
      enum: ['MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD'], 
      default: 'MM/DD/YYYY' 
    }
  }
}, { _id: false });

/**
 * User profile sub-schema
 */
const profileSchema = new Schema({
  avatar: {
    type: String,
    validate: {
      validator: function(v) {
        return !v || v.startsWith('/uploads/') || v.startsWith('http');
      },
      message: 'Avatar must be a valid URL or upload path'
    }
  },
  bio: {
    type: String,
    maxlength: [500, 'Bio cannot exceed 500 characters'],
    trim: true
  },
  website: {
    type: String,
    validate: {
      validator: function(v) {
        return !v || /^https?:\/\/.+/.test(v);
      },
      message: 'Website must be a valid URL'
    }
  },
  location: {
    type: String,
    maxlength: [100, 'Location cannot exceed 100 characters'],
    trim: true
  },
  title: {
    type: String,
    maxlength: [100, 'Title cannot exceed 100 characters'],
    trim: true
  },
  company: {
    type: String,
    maxlength: [100, 'Company cannot exceed 100 characters'],
    trim: true
  },
  skills: [{
    type: String,
    trim: true,
    maxlength: [50, 'Skill cannot exceed 50 characters']
  }],
  socialLinks: {
    github: String,
    linkedin: String,
    twitter: String,
    slack: String
  },
  preferences: {
    type: preferencesSchema,
    default: () => ({})
  }
}, { _id: false });

/**
 * Security event sub-schema for audit logging
 */
const securityEventSchema = new Schema({
  event: {
    type: String,
    required: true,
    enum: [
      'login', 'logout', 'password_change', 'password_reset',
      'email_change', '2fa_enabled', '2fa_disabled', 'account_locked',
      'suspicious_activity', 'role_changed'
    ]
  },
  timestamp: { type: Date, default: Date.now },
  ip: String,
  userAgent: String,
  details: Schema.Types.Mixed
}, { _id: false });

/**
 * Main User Schema
 */
const userSchema = new Schema({
  // Basic Information
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      },
      message: 'Please provide a valid email address'
    }
  },
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    validate: {
      validator: function(username) {
        return /^[a-zA-Z0-9_-]+$/.test(username);
      },
      message: 'Username can only contain letters, numbers, underscores, and hyphens'
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false // Don't include password in queries by default
  },
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },

  // Authentication & Security
  role: {
    type: String,
    enum: ['user', 'manager', 'admin'],
    default: 'user'
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  passwordChangedAt: Date,
  
  // Account Status
  isActive: {
    type: Boolean,
    default: true
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeenAt: {
    type: Date,
    default: Date.now
  },

  // Login Security
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  lastLoginAt: Date,
  lastLoginIP: String,

  // Two-Factor Authentication
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    select: false
  },
  twoFactorBackupCodes: [{
    type: String,
    select: false
  }],

  // Token Management
  tokenVersion: {
    type: Number,
    default: 0
  },

  // Profile Information
  profile: {
    type: profileSchema,
    default: () => ({})
  },

  // Team Associations
  teams: [{
    type: Schema.Types.ObjectId,
    ref: 'Team'
  }],

  // Social Features
  followers: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  following: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],

  // Activity Tracking
  tasksCreated: {
    type: Number,
    default: 0
  },
  tasksCompleted: {
    type: Number,
    default: 0
  },
  totalTimeTracked: {
    type: Number, // in minutes
    default: 0
  },

  // Security Audit Log
  securityEvents: [securityEventSchema],

  // Soft Delete
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date,
  deletedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive fields from JSON output
      delete ret.password;
      delete ret.twoFactorSecret;
      delete ret.twoFactorBackupCodes;
      delete ret.emailVerificationToken;
      delete ret.passwordResetToken;
      delete ret.securityEvents;
      delete ret.__v;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

/**
 * Virtual Properties
 */
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

userSchema.virtual('initials').get(function() {
  return `${this.firstName.charAt(0)}${this.lastName.charAt(0)}`.toUpperCase();
});

userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

userSchema.virtual('completionRate').get(function() {
  if (this.tasksCreated === 0) return 0;
  return Math.round((this.tasksCompleted / this.tasksCreated) * 100);
});

userSchema.virtual('followersCount').get(function() {
  return this.followers ? this.followers.length : 0;
});

userSchema.virtual('followingCount').get(function() {
  return this.following ? this.following.length : 0;
});

/**
 * Indexes for performance
 */
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ emailVerified: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ lastLoginAt: -1 });
userSchema.index({ isDeleted: 1 });

// Compound indexes
userSchema.index({ isActive: 1, role: 1 });
userSchema.index({ isActive: 1, emailVerified: 1 });

// Text search index
userSchema.index({
  firstName: 'text',
  lastName: 'text',
  username: 'text',
  email: 'text',
  'profile.bio': 'text',
  'profile.company': 'text'
});

/**
 * Pre-save middleware
 */
userSchema.pre('save', async function(next) {
  // Only hash password if it was modified
  if (!this.isModified('password')) return next();

  try {
    // Hash password
    this.password = await bcrypt.hash(this.password, config.security.saltRounds);
    
    // Set password changed timestamp
    if (!this.isNew) {
      this.passwordChangedAt = new Date();
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.pre('save', function(next) {
  // Convert email to lowercase
  if (this.isModified('email')) {
    this.email = this.email.toLowerCase();
  }
  
  // Update last seen when user is active
  if (this.isModified('isOnline') && this.isOnline) {
    this.lastSeenAt = new Date();
  }
  
  next();
});

/**
 * Instance Methods
 */

// Password comparison
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

// Handle failed login attempts
userSchema.methods.incLoginAttempts = async function() {
  const maxAttempts = config.security.maxLoginAttempts;
  const lockTime = config.security.lockoutTime * 60 * 1000; // Convert to milliseconds

  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };
  
  // If we have hit max attempts and it's not locked already, lock the account
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
    
    // Add security event
    this.securityEvents.push({
      event: 'account_locked',
      timestamp: new Date(),
      details: { reason: 'max_login_attempts', attempts: this.loginAttempts + 1 }
    });
  }

  return this.updateOne(updates);
};

// Reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Add security event
userSchema.methods.addSecurityEvent = function(event, details = {}) {
  this.securityEvents.push({
    event,
    timestamp: new Date(),
    details
  });
  
  // Keep only last 50 security events
  if (this.securityEvents.length > 50) {
    this.securityEvents = this.securityEvents.slice(-50);
  }
};

// Check if user can perform action
userSchema.methods.canPerformAction = function(action) {
  if (!this.isActive || this.isDeleted) return false;
  
  const rolePermissions = {
    user: ['read_own', 'update_own', 'create_task', 'comment'],
    manager: ['read_any', 'update_any', 'manage_team', 'view_reports'],
    admin: ['admin_all', 'manage_users', 'system_config']
  };
  
  const userPermissions = rolePermissions[this.role] || [];
  return userPermissions.includes(action) || userPermissions.includes('admin_all');
};

// Update activity stats
userSchema.methods.updateTaskStats = async function(action) {
  const updates = {};
  
  if (action === 'created') {
    updates.$inc = { tasksCreated: 1 };
  } else if (action === 'completed') {
    updates.$inc = { tasksCompleted: 1 };
  }
  
  if (Object.keys(updates).length > 0) {
    return this.updateOne(updates);
  }
};

// Get user's active sessions (would be stored in Redis)
userSchema.methods.getActiveSessions = async function() {
  // This would query Redis for active sessions
  // Placeholder for now
  return [];
};

// Follow another user
userSchema.methods.followUser = async function(userId) {
  if (this.following.includes(userId)) {
    return false; // Already following
  }
  
  this.following.push(userId);
  await this.save();
  
  // Add to the other user's followers
  await this.constructor.findByIdAndUpdate(userId, {
    $addToSet: { followers: this._id }
  });
  
  return true;
};

// Unfollow a user
userSchema.methods.unfollowUser = async function(userId) {
  const index = this.following.indexOf(userId);
  if (index === -1) {
    return false; // Not following
  }
  
  this.following.splice(index, 1);
  await this.save();
  
  // Remove from the other user's followers
  await this.constructor.findByIdAndUpdate(userId, {
    $pull: { followers: this._id }
  });
  
  return true;
};

/**
 * Static Methods
 */

// Find users by role
userSchema.statics.findByRole = function(role) {
  return this.find({ role, isActive: true, isDeleted: false });
};

// Search users
userSchema.statics.searchUsers = function(query, limit = 10) {
  return this.find(
    {
      $and: [
        { isActive: true, isDeleted: false },
        { $text: { $search: query } }
      ]
    },
    { score: { $meta: 'textScore' } }
  )
  .sort({ score: { $meta: 'textScore' } })
  .limit(limit)
  .select('firstName lastName username email profile.avatar role');
};

// Get user statistics
userSchema.statics.getStatistics = async function() {
  const stats = await this.aggregate([
    {
      $group: {
        _id: null,
        totalUsers: { $sum: 1 },
        activeUsers: {
          $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
        },
        verifiedUsers: {
          $sum: { $cond: [{ $eq: ['$emailVerified', true] }, 1, 0] }
        },
        adminUsers: {
          $sum: { $cond: [{ $eq: ['$role', 'admin'] }, 1, 0] }
        }
      }
    }
  ]);
  
  return stats[0] || {};
};

// Clean up expired tokens
userSchema.statics.cleanupExpiredTokens = async function() {
  const now = new Date();
  
  return this.updateMany(
    {
      $or: [
        { emailVerificationExpires: { $lt: now } },
        { passwordResetExpires: { $lt: now } }
      ]
    },
    {
      $unset: {
        emailVerificationToken: 1,
        emailVerificationExpires: 1,
        passwordResetToken: 1,
        passwordResetExpires: 1
      }
    }
  );
};

/**
 * Query Middleware
 */

// Exclude deleted users by default
userSchema.pre(/^find/, function() {
  if (!this.getQuery().includeDeleted) {
    this.find({ isDeleted: { $ne: true } });
  }
});

/**
 * Create and export model
 */
const User = mongoose.model('User', userSchema);

module.exports = User;