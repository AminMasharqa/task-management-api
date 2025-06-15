/**
 * Custom Validators
 * Specialized validation functions
 */

const mongoose = require('mongoose');

/**
 * Email validation
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
};

/**
 * Password strength validation
 */
const isStrongPassword = (password) => {
  if (!password || password.length < 8) return false;
  
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  return hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
};

/**
 * MongoDB ObjectId validation
 */
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

/**
 * URL validation
 */
const isValidUrl = (url) => {
  try {
    const urlObj = new URL(url);
    return ['http:', 'https:'].includes(urlObj.protocol);
  } catch {
    return false;
  }
};

/**
 * Username validation
 */
const isValidUsername = (username) => {
  if (!username || username.length < 3 || username.length > 30) return false;
  return /^[a-zA-Z0-9_-]+$/.test(username);
};

/**
 * Phone number validation (basic)
 */
const isValidPhone = (phone) => {
  const phoneRegex = /^\+?[\d\s\-\(\)]+$/;
  return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10;
};

/**
 * Hex color validation
 */
const isValidHexColor = (color) => {
  return /^#[0-9A-F]{6}$/i.test(color);
};

/**
 * Date validation (future dates only)
 */
const isFutureDate = (date) => {
  const inputDate = new Date(date);
  const now = new Date();
  return inputDate > now;
};

/**
 * File extension validation
 */
const hasValidExtension = (filename, allowedExtensions = []) => {
  const ext = filename.split('.').pop()?.toLowerCase();
  return allowedExtensions.includes(ext);
};

/**
 * Tag validation
 */
const isValidTag = (tag) => {
  return /^[a-zA-Z0-9_-]+$/.test(tag) && tag.length >= 2 && tag.length <= 30;
};

/**
 * IP address validation
 */
const isValidIP = (ip) => {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

/**
 * JSON validation
 */
const isValidJSON = (str) => {
  try {
    JSON.parse(str);
    return true;
  } catch {
    return false;
  }
};

/**
 * Sanitize string input
 */
const sanitizeString = (str) => {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[<>]/g, '');
};

/**
 * Validate array of ObjectIds
 */
const isValidObjectIdArray = (arr) => {
  return Array.isArray(arr) && arr.every(id => isValidObjectId(id));
};

/**
 * Check if string contains only letters and spaces
 */
const isOnlyLettersAndSpaces = (str) => {
  return /^[a-zA-Z\s]+$/.test(str);
};

/**
 * Validate priority level
 */
const isValidPriority = (priority) => {
  return ['low', 'medium', 'high', 'urgent'].includes(priority);
};

/**
 * Validate task status
 */
const isValidStatus = (status) => {
  return ['todo', 'in-progress', 'review', 'testing', 'completed', 'cancelled'].includes(status);
};

/**
 * Validate user role
 */
const isValidRole = (role) => {
  return ['user', 'manager', 'admin'].includes(role);
};

/**
 * Comprehensive validation function
 */
const validate = {
  email: isValidEmail,
  password: isStrongPassword,
  objectId: isValidObjectId,
  url: isValidUrl,
  username: isValidUsername,
  phone: isValidPhone,
  hexColor: isValidHexColor,
  futureDate: isFutureDate,
  fileExtension: hasValidExtension,
  tag: isValidTag,
  ip: isValidIP,
  json: isValidJSON,
  objectIdArray: isValidObjectIdArray,
  lettersAndSpaces: isOnlyLettersAndSpaces,
  priority: isValidPriority,
  status: isValidStatus,
  role: isValidRole
};

module.exports = {
  // Individual validators
  isValidEmail,
  isStrongPassword,
  isValidObjectId,
  isValidUrl,
  isValidUsername,
  isValidPhone,
  isValidHexColor,
  isFutureDate,
  hasValidExtension,
  isValidTag,
  isValidIP,
  isValidJSON,
  isValidObjectIdArray,
  isOnlyLettersAndSpaces,
  isValidPriority,
  isValidStatus,
  isValidRole,
  
  // Utility functions
  sanitizeString,
  
  // Consolidated validator object
  validate
};