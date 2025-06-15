/**
 * File Service
 * Handle file uploads, downloads, and management
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Ensure directory exists
 */
const ensureDirectory = async (dirPath) => {
  try {
    await fs.access(dirPath);
  } catch (error) {
    await fs.mkdir(dirPath, { recursive: true });
    logger.info('Directory created', { path: dirPath });
  }
};

/**
 * Generate secure filename
 */
const generateSecureFilename = (originalName) => {
  const ext = path.extname(originalName);
  const baseName = path.basename(originalName, ext).replace(/[^a-zA-Z0-9]/g, '-');
  const hash = crypto.randomBytes(8).toString('hex');
  const timestamp = Date.now();
  
  return `${baseName}-${timestamp}-${hash}${ext}`;
};

/**
 * Validate file type and size
 */
const validateFile = (file) => {
  const errors = [];

  // Check file size
  if (file.size > config.upload.maxFileSize) {
    errors.push(`File size exceeds ${Math.round(config.upload.maxFileSize / 1024 / 1024)}MB limit`);
  }

  // Check file type
  if (!config.upload.allowedTypes.includes(file.mimetype)) {
    errors.push(`File type ${file.mimetype} not allowed`);
  }

  return { isValid: errors.length === 0, errors };
};

/**
 * Save uploaded file
 */
const saveFile = async (file, category = 'general', subDir = '') => {
  try {
    const validation = validateFile(file);
    if (!validation.isValid) {
      throw new Error(validation.errors.join(', '));
    }

    // Create directory path
    const uploadDir = path.join(config.upload.uploadPath, category, subDir);
    await ensureDirectory(uploadDir);

    // Generate secure filename
    const filename = generateSecureFilename(file.originalname);
    const filePath = path.join(uploadDir, filename);

    // Save file
    await fs.writeFile(filePath, file.buffer);

    const fileInfo = {
      filename,
      originalName: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      path: filePath,
      url: `/uploads/${category}/${subDir ? subDir + '/' : ''}${filename}`,
      uploadedAt: new Date()
    };

    logger.info('File saved successfully', {
      filename,
      size: file.size,
      category,
      subDir
    });

    return fileInfo;

  } catch (error) {
    logger.error('Error saving file', error, {
      originalName: file?.originalname,
      size: file?.size
    });
    throw error;
  }
};

/**
 * Delete file
 */
const deleteFile = async (filePath) => {
  try {
    const fullPath = path.isAbsolute(filePath) 
      ? filePath 
      : path.join(config.upload.uploadPath, filePath);

    await fs.unlink(fullPath);
    
    logger.info('File deleted successfully', { path: fullPath });
    return true;

  } catch (error) {
    if (error.code === 'ENOENT') {
      logger.warn('File not found for deletion', { path: filePath });
      return false;
    }
    
    logger.error('Error deleting file', error, { path: filePath });
    throw error;
  }
};

/**
 * Get file info
 */
const getFileInfo = async (filePath) => {
  try {
    const fullPath = path.isAbsolute(filePath) 
      ? filePath 
      : path.join(config.upload.uploadPath, filePath);

    const stats = await fs.stat(fullPath);
    
    return {
      exists: true,
      size: stats.size,
      createdAt: stats.birthtime,
      modifiedAt: stats.mtime,
      path: fullPath
    };

  } catch (error) {
    if (error.code === 'ENOENT') {
      return { exists: false };
    }
    
    logger.error('Error getting file info', error, { path: filePath });
    throw error;
  }
};

/**
 * Clean up old files
 */
const cleanupOldFiles = async (category, maxAge = 30) => {
  try {
    const categoryPath = path.join(config.upload.uploadPath, category);
    const cutoffDate = new Date(Date.now() - maxAge * 24 * 60 * 60 * 1000);
    
    let deletedCount = 0;

    const processDirectory = async (dirPath) => {
      try {
        const items = await fs.readdir(dirPath, { withFileTypes: true });
        
        for (const item of items) {
          const itemPath = path.join(dirPath, item.name);
          
          if (item.isDirectory()) {
            await processDirectory(itemPath);
          } else {
            const stats = await fs.stat(itemPath);
            if (stats.birthtime < cutoffDate) {
              await fs.unlink(itemPath);
              deletedCount++;
            }
          }
        }
      } catch (error) {
        logger.warn('Error processing directory during cleanup', error, { dirPath });
      }
    };

    await processDirectory(categoryPath);
    
    logger.info('File cleanup completed', {
      category,
      maxAge,
      deletedCount
    });

    return deletedCount;

  } catch (error) {
    logger.error('Error during file cleanup', error, { category, maxAge });
    throw error;
  }
};

/**
 * Get directory size
 */
const getDirectorySize = async (dirPath) => {
  try {
    let totalSize = 0;

    const calculateSize = async (currentPath) => {
      const items = await fs.readdir(currentPath, { withFileTypes: true });
      
      for (const item of items) {
        const itemPath = path.join(currentPath, item.name);
        
        if (item.isDirectory()) {
          await calculateSize(itemPath);
        } else {
          const stats = await fs.stat(itemPath);
          totalSize += stats.size;
        }
      }
    };

    await calculateSize(dirPath);
    return totalSize;

  } catch (error) {
    logger.error('Error calculating directory size', error, { dirPath });
    throw error;
  }
};

/**
 * Format file size for display
 */
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Check disk space
 */
const checkDiskSpace = async () => {
  try {
    const uploadPath = config.upload.uploadPath;
    const totalSize = await getDirectorySize(uploadPath);
    
    return {
      usedSpace: totalSize,
      usedSpaceFormatted: formatFileSize(totalSize),
      uploadPath
    };

  } catch (error) {
    logger.error('Error checking disk space', error);
    throw error;
  }
};

module.exports = {
  saveFile,
  deleteFile,
  getFileInfo,
  cleanupOldFiles,
  getDirectorySize,
  formatFileSize,
  checkDiskSpace,
  validateFile,
  generateSecureFilename,
  ensureDirectory
};