import CryptoJS from 'crypto-js';

// Constants for encryption
export const PBKDF2_ITERATIONS = 100000;
export const KEY_SIZE = 256 / 32; // 256 bits in words
export const SALT_SIZE = 128 / 8; // 128 bits in bytes
export const IV_SIZE = 128 / 8; // 128 bits in bytes

// Key storage constants
export const DEK_KEY = 'data_encryption_key';
export const DEK_IV = 'data_encryption_iv';
export const DEK_SALT = 'data_encryption_salt';
export const DEK_VERSION = 'encryption_version';
export const ENCRYPTION_TYPE = 'encryption_type';

// Default encryption key (used until user sets their own)
// This provides basic security without requiring user setup
export const DEFAULT_ENCRYPTION_KEY = "FLUJO~";

// Encryption types
export enum EncryptionType {
  DEFAULT = 'default',
  USER = 'user'
}

export interface EncryptionMetadata {
  [DEK_KEY]: string;    // Encrypted DEK
  [DEK_IV]: string;     // IV used to encrypt DEK
  [DEK_SALT]: string;   // Salt used for key derivation
  [DEK_VERSION]: number; // Version of encryption scheme
  [ENCRYPTION_TYPE]?: EncryptionType; // Type of encryption (default or user)
}

// Error types for encryption/decryption
export enum EncryptionErrorType {
  METADATA_MISSING = 'metadata_missing',
  INITIALIZATION_FAILED = 'initialization_failed',
  INVALID_TOKEN = 'invalid_token',
  USER_PASSWORD_REQUIRED = 'user_password_required',
  USER_DEK_FAILED = 'user_dek_failed',
  DEFAULT_DEK_FAILED = 'default_dek_failed',
  UNKNOWN_ERROR = 'unknown_error'
}

export interface EncryptionError {
  type: EncryptionErrorType;
  message: string;
  details?: any;
}

// Error types for decryption
export enum DecryptionErrorType {
  DEK_ERROR = 'dek_error',
  INVALID_FORMAT = 'invalid_format',
  DECRYPTION_FAILED = 'decryption_failed',
  UNKNOWN_ERROR = 'unknown_error'
}

export interface DecryptionError {
  type: DecryptionErrorType;
  message: string;
  details?: any;
  dekError?: EncryptionError;
}

// Session token interface
export interface SessionToken {
  token: string;
  expiresAt: number;
}
