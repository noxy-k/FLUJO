import CryptoJS from 'crypto-js';
import { createLogger } from '@/utils/logger';
import { getDEK } from './encryptionKeyManager';
import { IV_SIZE, DecryptionErrorType, DecryptionError, EncryptionError } from './encryptionTypes';

// Create a logger instance for this file
const log = createLogger('utils/encryption/encryptionOperations');

/**
 * Encrypt data using the DEK
 * If no password or token is provided, uses the default key
 * 
 * @param text The text to encrypt
 * @param passwordOrToken Optional password or session token
 * @param isToken Whether the passwordOrToken is a session token
 * @returns The encrypted text or null if encryption failed
 */
export async function encryptWithPassword(text: string, passwordOrToken?: string, isToken: boolean = false): Promise<string | null> {
  log.debug('encryptWithPassword: Entering method', {
    textLength: text?.length || 0,
    hasPasswordOrToken: !!passwordOrToken,
    isToken
  });
  
  try {
    // Get the DEK
    const dekResult = await getDEK(passwordOrToken, isToken);
    
    // Check if DEK retrieval returned an error
    if (!dekResult || typeof dekResult !== 'object' || 'type' in dekResult) {
      log.error('encryptWithPassword: Failed to get DEK', dekResult);
      return null;
    }
    
    const dek = dekResult;
    
    // Generate a random IV for data encryption
    const iv = CryptoJS.lib.WordArray.random(IV_SIZE);
    
    // Encrypt the data with the DEK
    const encrypted = CryptoJS.AES.encrypt(
      text,
      dek,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    // Combine the IV and ciphertext for storage
    // Format: iv:ciphertext
    return iv.toString() + ':' + encrypted.toString();
  } catch (error) {
    log.error('encryptWithPassword: Failed to encrypt data:', error);
    return null;
  }
}

/**
 * Decrypt data using the DEK
 * If no password or token is provided, uses the default key
 * Returns either the decrypted string or a detailed error object
 * 
 * @param ciphertext The encrypted text to decrypt
 * @param passwordOrToken Optional password or session token
 * @param isToken Whether the passwordOrToken is a session token
 * @returns The decrypted text, an error object, or null if decryption failed
 */
export async function decryptWithPassword(ciphertext: string, passwordOrToken?: string, isToken: boolean = false): Promise<string | DecryptionError | null> {
  log.debug('decryptWithPassword: Entering method', {
    ciphertextLength: ciphertext?.length || 0,
    hasPasswordOrToken: !!passwordOrToken,
    isToken
  });
  
  if (!ciphertext) {
    log.error('decryptWithPassword: Empty or null ciphertext provided');
    return {
      type: DecryptionErrorType.INVALID_FORMAT,
      message: 'Empty or null ciphertext provided'
    };
  }
  
  try {
    // Get the DEK
    const dekResult = await getDEK(passwordOrToken, isToken);
    
    // Check if DEK retrieval returned an error
    if (!dekResult || typeof dekResult !== 'object' || 'type' in dekResult) {
      log.error('decryptWithPassword: Failed to get DEK', dekResult);
      return {
        type: DecryptionErrorType.DEK_ERROR,
        message: 'Failed to get Data Encryption Key',
        dekError: 'type' in dekResult ? dekResult as EncryptionError : undefined
      };
    }
    
    const dek = dekResult;
    
    // Validate ciphertext format
    if (!ciphertext.includes(':')) {
      log.error('decryptWithPassword: Invalid ciphertext format - missing delimiter', {
        format: 'No delimiter found',
        ciphertextPreview: ciphertext.substring(0, 20) + (ciphertext.length > 20 ? '...' : '')
      });
      return {
        type: DecryptionErrorType.INVALID_FORMAT,
        message: 'Invalid ciphertext format: missing delimiter'
      };
    }
    
    // Split the IV and ciphertext
    const parts = ciphertext.split(':');
    if (parts.length !== 2) {
      log.error('decryptWithPassword: Invalid ciphertext format - wrong number of parts', {
        partsCount: parts.length,
        expectedParts: 2,
        ciphertextPreview: ciphertext.substring(0, 20) + (ciphertext.length > 20 ? '...' : '')
      });
      return {
        type: DecryptionErrorType.INVALID_FORMAT,
        message: `Invalid ciphertext format: expected 2 parts, got ${parts.length}`
      };
    }
    
    const [ivPart, encryptedTextPart] = parts;
    
    // Validate IV format
    if (!ivPart || ivPart.length === 0) {
      log.error('decryptWithPassword: Invalid IV part - empty');
      return {
        type: DecryptionErrorType.INVALID_FORMAT,
        message: 'Invalid ciphertext format: empty IV'
      };
    }
    
    // Validate encrypted text format
    if (!encryptedTextPart || encryptedTextPart.length === 0) {
      log.error('decryptWithPassword: Invalid encrypted text part - empty');
      return {
        type: DecryptionErrorType.INVALID_FORMAT,
        message: 'Invalid ciphertext format: empty encrypted text'
      };
    }
    
    try {
      // Parse the IV
      const iv = CryptoJS.enc.Hex.parse(ivPart);
      
      // Decrypt the data with the DEK
      const decrypted = CryptoJS.AES.decrypt(
        encryptedTextPart,
        dek,
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }
      );
      
      // Check if decryption was successful
      const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);
      if (!decryptedString) {
        log.error('decryptWithPassword: Decryption produced empty result');
        return {
          type: DecryptionErrorType.DECRYPTION_FAILED,
          message: 'Decryption produced empty result'
        };
      }
      
      log.debug('decryptWithPassword: Successfully decrypted data', {
        decryptedLength: decryptedString.length
      });
      
      return decryptedString;
    } catch (decryptError) {
      log.error('decryptWithPassword: CryptoJS decryption failed', decryptError);
      return {
        type: DecryptionErrorType.DECRYPTION_FAILED,
        message: decryptError instanceof Error ? decryptError.message : 'CryptoJS decryption failed',
        details: decryptError
      };
    }
  } catch (error) {
    log.error('decryptWithPassword: Unexpected error during decryption:', error);
    return {
      type: DecryptionErrorType.UNKNOWN_ERROR,
      message: error instanceof Error ? error.message : 'Unknown error during decryption',
      details: error
    };
  }
}

/**
 * Simple utility function to encrypt a string with the default key
 * 
 * @param text The text to encrypt
 * @returns The encrypted text or null if encryption failed
 */
export async function encrypt(text: string): Promise<string | null> {
  return encryptWithPassword(text);
}

/**
 * Simple utility function to decrypt a string with the default key
 * 
 * @param ciphertext The encrypted text to decrypt
 * @returns The decrypted text or null if decryption failed
 */
export async function decrypt(ciphertext: string): Promise<string | null> {
  const result = await decryptWithPassword(ciphertext);
  if (typeof result === 'string') {
    return result;
  }
  return null;
}
