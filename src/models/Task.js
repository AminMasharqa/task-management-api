/**
 * Task Model
 * MongoDB schema for tasks with collaboration and productivity features
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Comment sub-schema for task discussions
 */
const commentSchema = new Schema({
  author: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: [true, 'Comment content is required'],
    trim: true,
    maxlength: [2000, 'Comment cannot exceed 2000 characters']
  },
  mentions: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  isEdited: {
    type: Boolean,
    default: false
  },
  editedAt: Date,
  reactions: [{
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    emoji: {
      type: String,
      enum: ['👍', '👎', '❤️', '😄', '😮', '😢', '😡']
    }
  }],
  attachments: [{
    filename: String,
    originalName: String,
    mimetype: String,
    size: Number,
    url: String
  }]
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

/**
 * Attachment sub-schema for task files
 */
const attachmentSchema = new Schema({
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  mimetype: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true,
    max: [10 * 1024 * 1024, 'File size cannot exceed 10MB'] // 10MB limit
  },
  url: {
    type: String,
    required: true
  },
  uploadedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  },
  description: {
    type: String,
    maxlength: [200, 'Attachment description cannot exceed 200 characters']
  },
  isDeleted: {
    type: Boolean,
    default: false
  }
}, { 
  timestamps: true 
});

/**
 * Time tracking entry sub-schema
 */
const timeEntrySchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  startTime: {
    type: Date,
    required: true
  },
  endTime: Date,
  duration: {
    type: Number, // in minutes
    min: [0, 'Duration cannot be negative']
  },
  description: {
    type: String,
    maxlength: [500, 'Time entry description cannot exceed 500 characters'],
    trim: true
  },
  isActive: {
    type: Boolean,
    default: false // true when timer is running
  },
  billable: {
    type: Boolean,
    default: false
  },
  hourlyRate: {
    type: Number,
    min: [0, 'Hourly rate cannot be negative']
  }
}, { 
  timestamps: true 
});

/**
 * Checklist item sub-schema
 */
const checklistItemSchema = new Schema({
  text: {
    type: String,
    required: [true, 'Checklist item text is required'],
    trim: true,
    maxlength: [200, 'Checklist item cannot exceed 200 characters']
  },
  completed: {
    type: Boolean,
    default: false
  },
  completedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  completedAt: Date,
  position: {
    type: Number,
    default: 0
  }
}, { 
  timestamps: true 
});

/**
 * Custom field sub-schema for extensibility
 */
const customFieldSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['text', 'number', 'date', 'select', 'multiselect', 'boolean', 'url'],
    required: true
  },
  value: Schema.Types.Mixed,
  options: [String], // For select/multiselect fields
  required: {
    type: Boolean,
    default: false
  }
}, { _id: false });

/**
 * Activity log entry sub-schema
 */
const activitySchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'created', 'updated', 'deleted', 'assigned', 'unassigned',
      'status_changed', 'priority_changed', 'due_date_set', 'due_date_changed',
      'comment_added', 'attachment_added', 'attachment_removed',
      'time_logged', 'checklist_updated', 'moved', 'duplicated'
    ]
  },
  details: {
    field: String,
    oldValue: Schema.Types.Mixed,
    newValue: Schema.Types.Mixed,
    description: String
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, { _id: false });

/**
 * Main Task Schema
 */
const taskSchema = new Schema({
  // Basic Task Information
  title: {
    type: String,
    required: [true, 'Task title is required'],
    trim: true,
    maxlength: [200, 'Task title cannot exceed 200 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [5000, 'Task description cannot exceed 5000 characters']
  },
  
  // Task Status and Priority
  status: {
    type: String,
    enum: {
      values: ['todo', 'in-progress', 'review', 'testing', 'completed', 'cancelled'],
      message: 'Status must be one of: todo, in-progress, review, testing, completed, cancelled'
    },
    default: 'todo'
  },
  priority: {
    type: String,
    enum: {
      values: ['low', 'medium', 'high', 'urgent'],
      message: 'Priority must be one of: low, medium, high, urgent'
    },
    default: 'medium'
  },
  
  // User Assignments
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assignedTo: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  collaborators: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  
  // Organization
  project: {
    type: Schema.Types.ObjectId,
    ref: 'Project'
  },
  epic: {
    type: Schema.Types.ObjectId,
    ref: 'Epic'
  },
  sprint: {
    type: Schema.Types.ObjectId,
    ref: 'Sprint'
  },
  labels: [{
    name: {
      type: String,
      required: true,
      trim: true
    },
    color: {
      type: String,
      match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex color']
    }
  }],
  tags: [{
    type: String,
    trim: true,
    lowercase: true,
    maxlength: [30, 'Tag cannot exceed 30 characters']
  }],
  
  // Time Management
  dueDate: {
    type: Date,
    validate: {
      validator: function(date) {
        return !date || date > new Date();
      },
      message: 'Due date must be in the future'
    }
  },
  startDate: Date,
  estimatedHours: {
    type: Number,
    min: [0, 'Estimated hours cannot be negative'],
    max: [1000, 'Estimated hours cannot exceed 1000']
  },
  actualHours: {
    type: Number,
    min: [0, 'Actual hours cannot be negative'],
    default: 0
  },
  
  // Progress Tracking
  progress: {
    type: Number,
    min: [0, 'Progress cannot be less than 0%'],
    max: [100, 'Progress cannot exceed 100%'],
    default: 0
  },
  
  // Task Relationships
  parentTask: {
    type: Schema.Types.ObjectId,
    ref: 'Task'
  },
  subtasks: [{
    type: Schema.Types.ObjectId,
    ref: 'Task'
  }],
  dependencies: [{
    task: {
      type: Schema.Types.ObjectId,
      ref: 'Task'
    },
    type: {
      type: String,
      enum: ['blocks', 'blocked_by', 'relates_to'],
      default: 'relates_to'
    }
  }],
  
  // Rich Content
  checklist: [checklistItemSchema],
  comments: [commentSchema],
  attachments: [attachmentSchema],
  timeEntries: [timeEntrySchema],
  
  // Custom Fields for Extensibility
  customFields: [customFieldSchema],
  
  // Activity and Audit
  activityLog: [activitySchema],
  
  // Completion Tracking
  completedAt: Date,
  completedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Modification Tracking
  updatedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Archive and Delete
  isArchived: {
    type: Boolean,
    default: false
  },
  archivedAt: Date,
  archivedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date,
  deletedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // Template Support
  isTemplate: {
    type: Boolean,
    default: false
  },
  templateCategory: String,
  templateTags: [String],
  
  // External Integration
  externalId: String,
  externalSource: {
    type: String,
    enum: ['github', 'jira', 'trello', 'asana', 'slack']
  },
  externalUrl: String
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive or internal fields
      delete ret.__v;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

/**
 * Virtual Properties
 */
taskSchema.virtual('isOverdue').get(function() {
  return this.dueDate && 
         this.dueDate < new Date() && 
         !['completed', 'cancelled'].includes(this.status);
});

taskSchema.virtual('daysPastDue').get(function() {
  if (!this.isOverdue) return 0;
  return Math.ceil((new Date() - this.dueDate) / (1000 * 60 * 60 * 24));
});

taskSchema.virtual('daysUntilDue').get(function() {
  if (!this.dueDate || this.isOverdue) return null;
  return Math.ceil((this.dueDate - new Date()) / (1000 * 60 * 60 * 24));
});

taskSchema.virtual('totalTimeSpent').get(function() {
  if (!this.timeEntries || this.timeEntries.length === 0) return 0;
  return this.timeEntries.reduce((total, entry) => {
    return total + (entry.duration || 0);
  }, 0);
});

taskSchema.virtual('checklistProgress').get(function() {
  if (!this.checklist || this.checklist.length === 0) return 100;
  const completed = this.checklist.filter(item => item.completed).length;
  return Math.round((completed / this.checklist.length) * 100);
});

taskSchema.virtual('commentsCount').get(function() {
  return this.comments ? this.comments.length : 0;
});

taskSchema.virtual('attachmentsCount').get(function() {
  return this.attachments ? this.attachments.filter(a => !a.isDeleted).length : 0;
});

taskSchema.virtual('hasActiveTimer').get(function() {
  return this.timeEntries && this.timeEntries.some(entry => entry.isActive);
});

taskSchema.virtual('assigneeCount').get(function() {
  return this.assignedTo ? this.assignedTo.length : 0;
});

/**
 * Indexes for performance
 */
taskSchema.index({ createdBy: 1 });
taskSchema.index({ assignedTo: 1 });
taskSchema.index({ status: 1 });
taskSchema.index({ priority: 1 });
taskSchema.index({ dueDate: 1 });
taskSchema.index({ createdAt: -1 });
taskSchema.index({ updatedAt: -1 });
taskSchema.index({ project: 1 });
taskSchema.index({ isDeleted: 1 });
taskSchema.index({ isArchived: 1 });
taskSchema.index({ isTemplate: 1 });

// Compound indexes for common queries
taskSchema.index({ status: 1, priority: 1 });
taskSchema.index({ assignedTo: 1, status: 1 });
taskSchema.index({ createdBy: 1, status: 1 });
taskSchema.index({ dueDate: 1, status: 1 });
taskSchema.index({ project: 1, status: 1 });
taskSchema.index({ isDeleted: 1, isArchived: 1 });

// Text search index
taskSchema.index({
  title: 'text',
  description: 'text',
  tags: 'text'
});

/**
 * Pre-save middleware
 */
taskSchema.pre('save', function(next) {
  // Auto-complete task if all checklist items are done
  if (this.checklist && this.checklist.length > 0) {
    const allCompleted = this.checklist.every(item => item.completed);
    if (allCompleted && this.status !== 'completed') {
      this.progress = 100;
    }
  }
  
  // Set completion timestamp
  if (this.isModified('status') && this.status === 'completed' && !this.completedAt) {
    this.completedAt = new Date();
  }
  
  // Clear completion timestamp if status changed from completed
  if (this.isModified('status') && this.status !== 'completed' && this.completedAt) {
    this.completedAt = undefined;
    this.completedBy = undefined;
  }
  
  // Validate parent-child relationship (prevent circular dependencies)
  if (this.parentTask && this.parentTask.equals(this._id)) {
    return next(new Error('Task cannot be its own parent'));
  }
  
  next();
});

taskSchema.pre('save', function(next) {
  // Log activity if this is an update
  if (!this.isNew && this.isModified()) {
    const modifiedFields = this.modifiedPaths();
    const importantFields = ['status', 'priority', 'assignedTo', 'dueDate', 'title', 'description'];
    
    for (const field of modifiedFields) {
      if (importantFields.includes(field)) {
        this.activityLog.push({
          user: this.updatedBy,
          action: 'updated',
          details: {
            field,
            description: `${field} updated`
          }
        });
      }
    }
    
    // Keep only last 100 activity entries
    if (this.activityLog.length > 100) {
      this.activityLog = this.activityLog.slice(-100);
    }
  }
  
  next();
});

/**
 * Instance Methods
 */

// Add comment to task
taskSchema.methods.addComment = function(userId, content, mentions = []) {
  const comment = {
    author: userId,
    content,
    mentions
  };
  
  this.comments.push(comment);
  this.activityLog.push({
    user: userId,
    action: 'comment_added',
    details: { description: 'Comment added' }
  });
  
  return this.save();
};

// Add time entry
taskSchema.methods.addTimeEntry = function(userId, startTime, endTime, description = '') {
  const duration = endTime ? Math.round((endTime - startTime) / (1000 * 60)) : 0;
  
  const timeEntry = {
    user: userId,
    startTime,
    endTime,
    duration,
    description
  };
  
  this.timeEntries.push(timeEntry);
  this.actualHours = this.totalTimeSpent / 60; // Convert minutes to hours
  
  this.activityLog.push({
    user: userId,
    action: 'time_logged',
    details: { 
      description: `Logged ${duration} minutes`,
      duration 
    }
  });
  
  return this.save();
};

// Start time tracking
taskSchema.methods.startTimer = function(userId, description = '') {
  // Stop any existing active timers for this user
  this.timeEntries.forEach(entry => {
    if (entry.user.equals(userId) && entry.isActive) {
      entry.isActive = false;
      entry.endTime = new Date();
      entry.duration = Math.round((entry.endTime - entry.startTime) / (1000 * 60));
    }
  });
  
  // Start new timer
  const timeEntry = {
    user: userId,
    startTime: new Date(),
    description,
    isActive: true
  };
  
  this.timeEntries.push(timeEntry);
  return this.save();
};

// Stop time tracking
taskSchema.methods.stopTimer = function(userId) {
  const activeEntry = this.timeEntries.find(entry => 
    entry.user.equals(userId) && entry.isActive
  );
  
  if (!activeEntry) {
    throw new Error('No active timer found for this user');
  }
  
  activeEntry.isActive = false;
  activeEntry.endTime = new Date();
  activeEntry.duration = Math.round((activeEntry.endTime - activeEntry.startTime) / (1000 * 60));
  
  this.actualHours = this.totalTimeSpent / 60;
  
  this.activityLog.push({
    user: userId,
    action: 'time_logged',
    details: { 
      description: `Stopped timer: ${activeEntry.duration} minutes`,
      duration: activeEntry.duration 
    }
  });
  
  return this.save();
};

// Assign users to task
taskSchema.methods.assignUsers = function(userIds, assignedBy) {
  const newAssignees = userIds.filter(id => 
    !this.assignedTo.some(assignee => assignee.equals(id))
  );
  
  this.assignedTo.push(...newAssignees);
  
  if (newAssignees.length > 0) {
    this.activityLog.push({
      user: assignedBy,
      action: 'assigned',
      details: { 
        description: `Assigned ${newAssignees.length} users`,
        userIds: newAssignees 
      }
    });
  }
  
  return this.save();
};

// Remove assignee
taskSchema.methods.unassignUser = function(userId, unassignedBy) {
  const index = this.assignedTo.findIndex(assignee => assignee.equals(userId));
  
  if (index !== -1) {
    this.assignedTo.splice(index, 1);
    
    this.activityLog.push({
      user: unassignedBy,
      action: 'unassigned',
      details: { 
        description: 'User unassigned',
        userId 
      }
    });
    
    return this.save();
  }
  
  return Promise.resolve(this);
};

// Update progress and auto-complete
taskSchema.methods.updateProgress = function(progress, userId) {
  this.progress = Math.max(0, Math.min(100, progress));
  
  // Auto-complete if progress reaches 100%
  if (this.progress === 100 && this.status !== 'completed') {
    this.status = 'completed';
    this.completedAt = new Date();
    this.completedBy = userId;
  }
  
  this.activityLog.push({
    user: userId,
    action: 'updated',
    details: { 
      field: 'progress',
      description: `Progress updated to ${this.progress}%`,
      newValue: this.progress 
    }
  });
  
  return this.save();
};

// Check if user has access to task
taskSchema.methods.hasAccess = function(userId, userRole) {
  // Admin and manager have access to all tasks
  if (['admin', 'manager'].includes(userRole)) {
    return true;
  }
  
  // Check if user is creator, assignee, or collaborator
  return this.createdBy.equals(userId) ||
         this.assignedTo.some(assignee => assignee.equals(userId)) ||
         this.collaborators.some(collaborator => collaborator.equals(userId));
};

// Duplicate task
taskSchema.methods.duplicate = function(userId, options = {}) {
  const duplicateData = this.toObject();
  
  // Remove fields that shouldn't be duplicated
  delete duplicateData._id;
  delete duplicateData.createdAt;
  delete duplicateData.updatedAt;
  delete duplicateData.completedAt;
  delete duplicateData.completedBy;
  delete duplicateData.comments;
  delete duplicateData.timeEntries;
  delete duplicateData.activityLog;
  
  // Modify title to indicate duplicate
  duplicateData.title = `${duplicateData.title} (Copy)`;
  duplicateData.status = 'todo';
  duplicateData.progress = 0;
  duplicateData.createdBy = userId;
  
  // Apply options
  if (options.assignToCreator) {
    duplicateData.assignedTo = [userId];
  }
  if (options.clearDueDate) {
    delete duplicateData.dueDate;
  }
  if (options.clearAssignees) {
    duplicateData.assignedTo = [];
  }
  
  return new this.constructor(duplicateData);
};

/**
 * Static Methods
 */

// Find tasks by status
taskSchema.statics.findByStatus = function(status, userId = null) {
  const query = { status, isDeleted: false };
  
  if (userId) {
    query.$or = [
      { createdBy: userId },
      { assignedTo: userId },
      { collaborators: userId }
    ];
  }
  
  return this.find(query);
};

// Find overdue tasks
taskSchema.statics.findOverdue = function(userId = null) {
  const query = {
    dueDate: { $lt: new Date() },
    status: { $nin: ['completed', 'cancelled'] },
    isDeleted: false
  };
  
  if (userId) {
    query.$or = [
      { createdBy: userId },
      { assignedTo: userId }
    ];
  }
  
  return this.find(query);
};

// Get task statistics
taskSchema.statics.getStatistics = async function(userId = null, filters = {}) {
  const matchStage = { isDeleted: false, ...filters };
  
  if (userId) {
    matchStage.$or = [
      { createdBy: userId },
      { assignedTo: userId },
      { collaborators: userId }
    ];
  }
  
  const stats = await this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: null,
        totalTasks: { $sum: 1 },
        completedTasks: {
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        },
        inProgressTasks: {
          $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] }
        },
        overdueTasks: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $lt: ['$dueDate', new Date()] },
                  { $nin: ['$status', ['completed', 'cancelled']] }
                ]
              },
              1,
              0
            ]
          }
        },
        averageProgress: { $avg: '$progress' },
        totalTimeSpent: { $sum: '$actualHours' }
      }
    }
  ]);
  
  return stats[0] || {};
};

// Search tasks
taskSchema.statics.searchTasks = function(query, userId = null, limit = 20) {
  const searchQuery = {
    $and: [
      { isDeleted: false },
      { $text: { $search: query } }
    ]
  };
  
  if (userId) {
    searchQuery.$and.push({
      $or: [
        { createdBy: userId },
        { assignedTo: userId },
        { collaborators: userId }
      ]
    });
  }
  
  return this.find(searchQuery, { score: { $meta: 'textScore' } })
    .sort({ score: { $meta: 'textScore' } })
    .limit(limit);
};

/**
 * Query Middleware
 */

// Exclude deleted tasks by default
taskSchema.pre(/^find/, function() {
  if (!this.getQuery().includeDeleted) {
    this.find({ isDeleted: { $ne: true } });
  }
});

/**
 * Create and export model
 */
const Task = mongoose.model('Task', taskSchema);

module.exports = Task;