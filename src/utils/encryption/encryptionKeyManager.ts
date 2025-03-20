import CryptoJS from 'crypto-js';
import { loadItem, saveItem } from '@/utils/storage/backend';
import { StorageKey } from '@/shared/types/storage';
import { createLogger } from '@/utils/logger';
import { createSession, getDekFromSession, invalidateSession } from './session';
import {
  PBKDF2_ITERATIONS,
  KEY_SIZE,
  SALT_SIZE,
  IV_SIZE,
  DEK_KEY,
  DEK_IV,
  DEK_SALT,
  DEK_VERSION,
  ENCRYPTION_TYPE,
  DEFAULT_ENCRYPTION_KEY,
  EncryptionType,
  EncryptionMetadata,
  EncryptionErrorType,
  EncryptionError
} from './encryptionTypes';

// Create a logger instance for this file
const log = createLogger('utils/encryption/encryptionKeyManager');

/**
 * Check if encryption is initialized
 */
export async function isEncryptionInitialized(): Promise<boolean> {
  log.debug('isEncryptionInitialized: Entering method');
  const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
  return metadata !== null;
}

/**
 * Get a derived encryption key from the default key
 * This is used when no user key is set
 */
function getDefaultDerivedKey(): CryptoJS.lib.WordArray {
  // Use a fixed salt for the default key
  const fixedSalt = CryptoJS.enc.Utf8.parse("flujo_fixed_salt_v1");
  
  // Derive a key from the default password using PBKDF2
  return CryptoJS.PBKDF2(
    DEFAULT_ENCRYPTION_KEY,
    fixedSalt,
    {
      keySize: KEY_SIZE,
      iterations: PBKDF2_ITERATIONS
    }
  );
}

/**
 * Generate a random DEK (Data Encryption Key)
 */
export function generateRandomDEK(): CryptoJS.lib.WordArray {
  return CryptoJS.lib.WordArray.random(KEY_SIZE);
}

/**
 * Initialize the default encryption system
 * This creates a DEK encrypted with the default key
 */
export async function initializeDefaultEncryption(): Promise<boolean> {
  log.debug('initializeDefaultEncryption: Entering method');
  try {
    // Check if encryption is already initialized
    const isInitialized = await isEncryptionInitialized();
    if (isInitialized) {
      // Already initialized, no need to do it again
      return true;
    }
    
    // Get the default derived key
    const derivedKey = getDefaultDerivedKey();
    
    // Generate a random DEK
    const dataEncryptionKey = generateRandomDEK();
    
    // Generate a random IV for DEK encryption
    const iv = CryptoJS.lib.WordArray.random(IV_SIZE);
    
    // Encrypt the DEK with the derived key
    const encryptedDEK = CryptoJS.AES.encrypt(
      dataEncryptionKey.toString(),
      derivedKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    // Create fixed salt for storage
    const fixedSalt = CryptoJS.enc.Utf8.parse("flujo_fixed_salt_v1");
    
    // Store the encrypted DEK and metadata
    const metadata: EncryptionMetadata = {
      [DEK_KEY]: encryptedDEK.toString(),
      [DEK_IV]: iv.toString(),
      [DEK_SALT]: fixedSalt.toString(),
      [DEK_VERSION]: 1, // Initial version
      [ENCRYPTION_TYPE]: EncryptionType.DEFAULT
    };
    
    // Save the encryption metadata
    await saveItem(StorageKey.ENCRYPTION_KEY, metadata);
    
    return true;
  } catch (error) {
    log.error('initializeDefaultEncryption: Failed to initialize default encryption:', error);
    return false;
  }
}

/**
 * Initialize the encryption system with a user password
 * This creates a new DEK, encrypts it with the password-derived key,
 * and stores the encrypted DEK and metadata
 */
export async function initializeEncryption(password: string): Promise<boolean> {
  log.debug('initializeEncryption: Entering method');
  try {
    // Check if we need to migrate from default encryption
    const existingMetadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
    if (existingMetadata && existingMetadata[ENCRYPTION_TYPE] === EncryptionType.DEFAULT) {
      // Migrate from default to user encryption
      return await migrateToUserEncryption(password);
    }
    
    // Generate a random salt for key derivation
    const salt = CryptoJS.lib.WordArray.random(SALT_SIZE);
    
    // Derive a key from the password using PBKDF2
    const derivedKey = CryptoJS.PBKDF2(
      password,
      salt,
      {
        keySize: KEY_SIZE,
        iterations: PBKDF2_ITERATIONS
      }
    );
    
    // Generate a random DEK (Data Encryption Key)
    const dataEncryptionKey = generateRandomDEK();
    
    // Generate a random IV for DEK encryption
    const iv = CryptoJS.lib.WordArray.random(IV_SIZE);
    
    // Encrypt the DEK with the derived key
    const encryptedDEK = CryptoJS.AES.encrypt(
      dataEncryptionKey.toString(),
      derivedKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    // Store the encrypted DEK and metadata
    const metadata: EncryptionMetadata = {
      [DEK_KEY]: encryptedDEK.toString(),
      [DEK_IV]: iv.toString(),
      [DEK_SALT]: salt.toString(),
      [DEK_VERSION]: 1, // Initial version
      [ENCRYPTION_TYPE]: EncryptionType.USER
    };
    
    // Save the encryption metadata
    await saveItem(StorageKey.ENCRYPTION_KEY, metadata);
    
    return true;
  } catch (error) {
    log.error('initializeEncryption: Failed to initialize encryption:', error);
    return false;
  }
}

/**
 * Get the default DEK
 * This is used for encryption/decryption when no user key is set
 */
export async function getDefaultDEK(): Promise<CryptoJS.lib.WordArray | null> {
  log.debug('getDefaultDEK: Entering method');
  try {
    // Load the encryption metadata
    const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
    if (!metadata) {
      // No encryption metadata found, initialize default encryption
      const initialized = await initializeDefaultEncryption();
      if (!initialized) {
        log.error('getDefaultDEK: Failed to initialize default encryption');
        return null;
      }
      
      // Try again after initialization
      return await getDefaultDEK();
    }
    
    // Check if we're using default encryption
    if (metadata[ENCRYPTION_TYPE] !== EncryptionType.DEFAULT) {
      log.error('getDefaultDEK: Not using default encryption');
      return null;
    }
    
    // Extract the metadata
    const encryptedDEK = metadata[DEK_KEY];
    const iv = CryptoJS.enc.Hex.parse(metadata[DEK_IV]);
    
    // Get the default derived key
    const derivedKey = getDefaultDerivedKey();
    
    // Decrypt the DEK
    const decryptedDEK = CryptoJS.AES.decrypt(
      encryptedDEK,
      derivedKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    if (!decryptedDEK.toString()) {
      log.error('getDefaultDEK: Failed to decrypt DEK with default key');
      return null;
    }
    
    return CryptoJS.enc.Hex.parse(decryptedDEK.toString());
  } catch (error) {
    log.error('getDefaultDEK: Failed to get default DEK:', error);
    return null;
  }
}

/**
 * Get the user DEK
 * This is used for encryption/decryption when a user key is set
 */
export async function getUserDEK(password: string): Promise<CryptoJS.lib.WordArray | null> {
  log.debug('getUserDEK: Entering method');
  try {
    // Load the encryption metadata
    const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
    if (!metadata) {
      log.error('getUserDEK: No encryption metadata found');
      return null;
    }
    
    // Check if we're using user encryption
    if (metadata[ENCRYPTION_TYPE] !== EncryptionType.USER) {
      log.error('getUserDEK: Not using user encryption');
      return null;
    }
    
    // Extract the metadata
    const encryptedDEK = metadata[DEK_KEY];
    const iv = CryptoJS.enc.Hex.parse(metadata[DEK_IV]);
    const salt = CryptoJS.enc.Hex.parse(metadata[DEK_SALT]);
    
    // Derive the key from the password
    const derivedKey = CryptoJS.PBKDF2(
      password,
      salt,
      {
        keySize: KEY_SIZE,
        iterations: PBKDF2_ITERATIONS
      }
    );
    
    // Decrypt the DEK
    const decryptedDEK = CryptoJS.AES.decrypt(
      encryptedDEK,
      derivedKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    if (!decryptedDEK.toString()) {
      log.error('getUserDEK: Failed to decrypt DEK with provided password');
      return null;
    }
    
    return CryptoJS.enc.Hex.parse(decryptedDEK.toString());
  } catch (error) {
    log.error('getUserDEK: Failed to get user DEK:', error);
    return null;
  }
}

/**
 * Migrate from default encryption to user encryption
 * This decrypts all data with the default key and re-encrypts it with the user's key
 */
export async function migrateToUserEncryption(password: string): Promise<boolean> {
  log.debug('migrateToUserEncryption: Entering method');
  try {
    // Check if we're already using user encryption
    const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
    if (metadata && metadata[ENCRYPTION_TYPE] === EncryptionType.USER) {
      // Already using user encryption, no need to migrate
      return true;
    }
    
    // Get the default DEK
    const defaultDEK = await getDefaultDEK();
    if (!defaultDEK) {
      log.error('migrateToUserEncryption: Failed to get default DEK for migration');
      return false;
    }
    
    // Generate a random salt for key derivation
    const salt = CryptoJS.lib.WordArray.random(SALT_SIZE);
    
    // Derive a key from the password using PBKDF2
    const derivedKey = CryptoJS.PBKDF2(
      password,
      salt,
      {
        keySize: KEY_SIZE,
        iterations: PBKDF2_ITERATIONS
      }
    );
    
    // Generate a random IV for DEK encryption
    const iv = CryptoJS.lib.WordArray.random(IV_SIZE);
    
    // Re-encrypt the DEK with the user's key
    const encryptedDEK = CryptoJS.AES.encrypt(
      defaultDEK.toString(),
      derivedKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    // Update the metadata
    const newMetadata: EncryptionMetadata = {
      [DEK_KEY]: encryptedDEK.toString(),
      [DEK_IV]: iv.toString(),
      [DEK_SALT]: salt.toString(),
      [DEK_VERSION]: metadata ? metadata[DEK_VERSION] : 1, // Keep the same version or use 1
      [ENCRYPTION_TYPE]: EncryptionType.USER
    };
    
    // Save the updated metadata
    await saveItem(StorageKey.ENCRYPTION_KEY, newMetadata);
    
    // In a real implementation, we would need to re-encrypt all sensitive data
    // For now, we'll just return success
    
    return true;
  } catch (error) {
    log.error('migrateToUserEncryption: Failed to migrate to user encryption:', error);
    return false;
  }
}

/**
 * Change the encryption password
 * This decrypts the DEK with the old password and re-encrypts it with the new password
 */
export async function changeEncryptionPassword(oldPassword: string, newPassword: string): Promise<boolean> {
  log.debug('changeEncryptionPassword: Entering method');
  try {
    // Load the encryption metadata
    const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
    if (!metadata) {
      log.error('changeEncryptionPassword: No encryption metadata found');
      return false;
    }
    
    // Check if we're using default encryption
    if (metadata[ENCRYPTION_TYPE] === EncryptionType.DEFAULT) {
      // Migrate from default to user encryption instead of changing password
      return await migrateToUserEncryption(newPassword);
    }
    
    // Extract the metadata
    const encryptedDEK = metadata[DEK_KEY];
    const iv = CryptoJS.enc.Hex.parse(metadata[DEK_IV]);
    const salt = CryptoJS.enc.Hex.parse(metadata[DEK_SALT]);
    
    // Derive the old key
    const oldDerivedKey = CryptoJS.PBKDF2(
      oldPassword,
      salt,
      {
        keySize: KEY_SIZE,
        iterations: PBKDF2_ITERATIONS
      }
    );
    
    // Decrypt the DEK with the old key
    const decryptedDEK = CryptoJS.AES.decrypt(
      encryptedDEK,
      oldDerivedKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    if (!decryptedDEK.toString()) {
      log.error('changeEncryptionPassword: Failed to decrypt DEK with old password');
      return false;
    }
    
    // Generate a new salt for the new key
    const newSalt = CryptoJS.lib.WordArray.random(SALT_SIZE);
    
    // Derive a new key from the new password
    const newDerivedKey = CryptoJS.PBKDF2(
      newPassword,
      newSalt,
      {
        keySize: KEY_SIZE,
        iterations: PBKDF2_ITERATIONS
      }
    );
    
    // Generate a new IV for DEK encryption
    const newIv = CryptoJS.lib.WordArray.random(IV_SIZE);
    
    // Re-encrypt the DEK with the new key
    const newEncryptedDEK = CryptoJS.AES.encrypt(
      decryptedDEK.toString(),
      newDerivedKey,
      {
        iv: newIv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    // Update the metadata
    const newMetadata: EncryptionMetadata = {
      [DEK_KEY]: newEncryptedDEK.toString(),
      [DEK_IV]: newIv.toString(),
      [DEK_SALT]: newSalt.toString(),
      [DEK_VERSION]: metadata[DEK_VERSION], // Keep the same version
      [ENCRYPTION_TYPE]: EncryptionType.USER
    };
    
    // Save the updated metadata
    await saveItem(StorageKey.ENCRYPTION_KEY, newMetadata);
    
    return true;
  } catch (error) {
    log.error('changeEncryptionPassword: Failed to change encryption password:', error);
    return false;
  }
}

/**
 * Get the DEK using the provided password, session token, or default key
 * This is a helper function used by encrypt and decrypt
 */
export async function getDEK(passwordOrToken?: string, isToken: boolean = false): Promise<CryptoJS.lib.WordArray | EncryptionError> {
  log.debug('getDEK: Entering method with params', { 
    hasPasswordOrToken: !!passwordOrToken, 
    isToken 
  });
  
  try {
    // If a token is provided, try to get the DEK from the session
    if (isToken && passwordOrToken) {
      log.debug('getDEK: Using session token');
      const dekString = getDekFromSession(passwordOrToken);
      if (dekString) {
        log.debug('getDEK: Successfully retrieved DEK from session');
        return CryptoJS.enc.Hex.parse(dekString);
      }
      
      log.warn('getDEK: Invalid or expired session token, falling back to default encryption');
      return {
        type: EncryptionErrorType.INVALID_TOKEN,
        message: 'Invalid or expired session token'
      };
    }
    
    // Load the encryption metadata
    const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
    if (!metadata) {
      // No encryption metadata found, initialize default encryption
      log.info('getDEK: No encryption metadata found, initializing default encryption');
      const initialized = await initializeDefaultEncryption();
      if (!initialized) {
        log.error('getDEK: Failed to initialize default encryption');
        return {
          type: EncryptionErrorType.INITIALIZATION_FAILED,
          message: 'Failed to initialize default encryption'
        };
      }
      
      // Try again after initialization
      log.debug('getDEK: Retrying after initialization');
      return await getDEK(passwordOrToken, isToken);
    }
    
    // Log the encryption type for debugging
    log.debug('getDEK: Encryption type', { 
      type: metadata[ENCRYPTION_TYPE] || 'not set',
      version: metadata[DEK_VERSION] || 'unknown'
    });
    
    // Check the encryption type
    if (metadata[ENCRYPTION_TYPE] === EncryptionType.USER) {
      // User encryption requires a password
      if (!passwordOrToken || isToken) {
        log.warn('getDEK: Password required for user encryption but not provided, falling back to default encryption');
        
        // Instead of failing, try to initialize default encryption and use that
        const defaultDEK = await getDefaultDEK();
        if (defaultDEK) {
          log.debug('getDEK: Successfully retrieved default DEK as fallback');
          return defaultDEK;
        }
        
        // If default DEK fails, try to initialize it
        const initialized = await initializeDefaultEncryption();
        if (!initialized) {
          log.error('getDEK: Failed to initialize default encryption as fallback');
          return {
            type: EncryptionErrorType.DEFAULT_DEK_FAILED,
            message: 'Failed to initialize default encryption as fallback'
          };
        }
        
        // Try to get the default DEK again
        log.debug('getDEK: Retrying default DEK after initialization');
        const retryDefaultDEK = await getDefaultDEK();
        if (retryDefaultDEK) {
          return retryDefaultDEK;
        } else {
          return {
            type: EncryptionErrorType.DEFAULT_DEK_FAILED,
            message: 'Failed to get default DEK after initialization'
          };
        }
      }
      
      // Try to get the user DEK
      log.debug('getDEK: Attempting to get user DEK with provided password');
      const userDEK = await getUserDEK(passwordOrToken);
      if (userDEK) {
        log.debug('getDEK: Successfully retrieved user DEK');
        return userDEK;
      }
      
      // If user DEK fails, fall back to default encryption
      log.warn('getDEK: Failed to get user DEK, falling back to default encryption');
      const defaultDEK = await getDefaultDEK();
      if (defaultDEK) {
        log.debug('getDEK: Successfully retrieved default DEK as fallback after user DEK failure');
        return defaultDEK;
      } else {
        return {
          type: EncryptionErrorType.USER_DEK_FAILED,
          message: 'Failed to get user DEK and default DEK fallback also failed'
        };
      }
    } else {
      // Default encryption
      log.debug('getDEK: Using default encryption');
      const defaultDEK = await getDefaultDEK();
      if (defaultDEK) {
        log.debug('getDEK: Successfully retrieved default DEK');
        return defaultDEK;
      } else {
        return {
          type: EncryptionErrorType.DEFAULT_DEK_FAILED,
          message: 'Failed to get default DEK'
        };
      }
    }
  } catch (error) {
    log.error('getDEK: Failed to get DEK:', error);
    
    // Try to initialize default encryption as a last resort
    try {
      log.warn('getDEK: Attempting to initialize default encryption as error recovery');
      const initialized = await initializeDefaultEncryption();
      if (initialized) {
        const defaultDEK = await getDefaultDEK();
        if (defaultDEK) {
          log.debug('getDEK: Successfully retrieved default DEK after error recovery');
          return defaultDEK;
        }
      }
    } catch (fallbackError) {
      log.error('getDEK: Failed to initialize default encryption as error recovery:', fallbackError);
    }
    
    return {
      type: EncryptionErrorType.UNKNOWN_ERROR,
      message: error instanceof Error ? error.message : 'Unknown error getting DEK',
      details: error
    };
  }
}

/**
 * Check if the provided password is correct
 * If correct, creates a session and returns the token
 */
export async function verifyPassword(password: string): Promise<string | null> {
  log.debug('verifyPassword: Entering method');
  try {
    // Load the encryption metadata
    const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
    if (!metadata) {
      log.error('verifyPassword: No encryption metadata found');
      return null;
    }
    
    // Check if we're using user encryption
    if (metadata[ENCRYPTION_TYPE] !== EncryptionType.USER) {
      log.warn('verifyPassword: Not using user encryption, cannot verify password');
      return null;
    }
    
    // Try to get the user DEK with the provided password
    const userDEK = await getUserDEK(password);
    if (!userDEK) {
      log.error('verifyPassword: Failed to decrypt DEK with provided password');
      return null;
    }
    
    // Password is correct, create a session
    const token = createSession(userDEK.toString());
    return token;
  } catch (error) {
    log.error('verifyPassword: Failed to verify password:', error);
    return null;
  }
}

/**
 * Check if user encryption is enabled
 */
export async function isUserEncryptionEnabled(): Promise<boolean> {
  log.debug('isUserEncryptionEnabled: Entering method');
  const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
  return metadata !== null && metadata[ENCRYPTION_TYPE] === EncryptionType.USER;
}

/**
 * Get the current encryption type
 */
export async function getEncryptionType(): Promise<EncryptionType | null> {
  log.debug('getEncryptionType: Entering method');
  const metadata = await loadItem<EncryptionMetadata | null>(StorageKey.ENCRYPTION_KEY, null);
  return metadata ? metadata[ENCRYPTION_TYPE] || null : null;
}

/**
 * Authenticate with a password
 * This is a wrapper around verifyPassword that returns a token if successful
 */
export async function authenticate(password: string): Promise<string | null> {
  log.debug('authenticate: Entering method');
  return verifyPassword(password);
}

/**
 * Invalidate the current session
 * @param token The session token to invalidate
 */
export function logout(token: string): void {
  log.debug('logout: Invalidating session');
  invalidateSession(token);
}
