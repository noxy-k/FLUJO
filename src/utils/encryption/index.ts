/**
 * Encryption Module
 * 
 * This module provides encryption and decryption functionality for the application.
 * It supports both default (application-managed) encryption and user-based encryption.
 */

// Re-export types
export type {
  EncryptionType,
  EncryptionErrorType,
  EncryptionError,
  DecryptionErrorType,
  DecryptionError,
  SessionToken
} from './encryptionTypes';

// Re-export key management functions
export {
  isEncryptionInitialized,
  initializeDefaultEncryption,
  initializeEncryption,
  migrateToUserEncryption,
  changeEncryptionPassword,
  verifyPassword,
  logout,
  isUserEncryptionEnabled,
  getEncryptionType,
  authenticate
} from './encryptionKeyManager';

// Re-export encryption operations
export {
  encryptWithPassword,
  decryptWithPassword,
  encrypt,
  decrypt
} from './encryptionOperations';

// Export session functions
export { createSession, getDekFromSession } from './session';
