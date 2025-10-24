-- TOTP (Time-based One-Time Password) Tables for E-Halal System
-- Run this SQL to add TOTP support to your existing database

-- Table for storing TOTP secrets for administrators
CREATE TABLE `admin_totp_secrets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `admin_id` int(11) NOT NULL,
  `secret` varchar(64) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `admin_id` (`admin_id`),
  FOREIGN KEY (`admin_id`) REFERENCES `admin` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table for storing backup codes for administrators
CREATE TABLE `admin_backup_codes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `admin_id` int(11) NOT NULL,
  `code_hash` varchar(255) NOT NULL,
  `used` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `admin_id` (`admin_id`),
  FOREIGN KEY (`admin_id`) REFERENCES `admin` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table for tracking TOTP verification attempts
CREATE TABLE `admin_totp_attempts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `admin_id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `attempts` int(11) NOT NULL DEFAULT 0,
  `last_attempt` timestamp NOT NULL DEFAULT current_timestamp(),
  `locked_until` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `admin_ip` (`admin_id`, `ip_address`),
  FOREIGN KEY (`admin_id`) REFERENCES `admin` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Add TOTP enabled flag to admin table (optional, for easier checking)
ALTER TABLE `admin` ADD COLUMN `totp_enabled` tinyint(1) NOT NULL DEFAULT 0 AFTER `role`;

-- Create indexes for better performance
CREATE INDEX `idx_admin_totp_secrets_admin_id` ON `admin_totp_secrets` (`admin_id`);
CREATE INDEX `idx_admin_backup_codes_admin_id` ON `admin_backup_codes` (`admin_id`, `used`);
CREATE INDEX `idx_admin_totp_attempts_admin_ip` ON `admin_totp_attempts` (`admin_id`, `ip_address`);
CREATE INDEX `idx_admin_totp_attempts_locked` ON `admin_totp_attempts` (`locked_until`);
