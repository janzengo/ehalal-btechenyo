<?php
declare(strict_types=1);

require_once __DIR__ . '/Database.php';

/**
 * TOTP (Time-based One-Time Password) Implementation
 * Compatible with Google Authenticator and other RFC 6238 compliant apps
 */
class TOTP {
    private $db;
    private $issuer = 'E-Halal BTECHenyo';
    private $algorithm = 'sha1';
    private $digits = 6;
    private $period = 30; // 30 seconds
    
    public function __construct() {
        $this->db = Database::getInstance();
    }
    
    /**
     * Generate a random secret key for TOTP
     * 
     * @param int $length Length of the secret (default 32 bytes = 256 bits)
     * @return string Base32 encoded secret
     */
    public function generateSecret(int $length = 32): string {
        $bytes = random_bytes($length);
        return $this->base32Encode($bytes);
    }
    
    /**
     * Generate TOTP code for given secret and time
     * 
     * @param string $secret Base32 encoded secret
     * @param int|null $time Unix timestamp (defaults to current time)
     * @return string 6-digit TOTP code
     */
    public function generateCode(string $secret, ?int $time = null): string {
        $time = $time ?? time();
        $timeSlice = floor($time / $this->period);
        
        $secretBytes = $this->base32Decode($secret);
        $timeBytes = pack('N*', 0, $timeSlice);
        
        $hash = hash_hmac($this->algorithm, $timeBytes, $secretBytes, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % pow(10, $this->digits);
        
        return str_pad((string)$code, $this->digits, '0', STR_PAD_LEFT);
    }
    
    /**
     * Verify TOTP code with tolerance for clock skew
     * 
     * @param string $secret Base32 encoded secret
     * @param string $code TOTP code to verify
     * @param int $tolerance Number of time steps to allow (default 1)
     * @return bool True if code is valid
     */
    public function verifyCode(string $secret, string $code, int $tolerance = 1): bool {
        $time = time();
        
        for ($i = -$tolerance; $i <= $tolerance; $i++) {
            $testCode = $this->generateCode($secret, $time + ($i * $this->period));
            if (hash_equals($testCode, $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate QR code URL for Google Authenticator
     * 
     * @param string $secret Base32 encoded secret
     * @param string $account Account name (username or email)
     * @return string QR code URL
     */
    public function getQRCodeUrl(string $secret, string $account): string {
        $url = sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d',
            urlencode($this->issuer),
            urlencode($account),
            $secret,
            urlencode($this->issuer),
            strtoupper($this->algorithm),
            $this->digits,
            $this->period
        );
        
        return $url;
    }
    
    /**
     * Generate QR code image data URL
     * 
     * @param string $secret Base32 encoded secret
     * @param string $account Account name
     * @param int $size QR code size in pixels
     * @return string Data URL for QR code image
     */
    public function getQRCodeImage(string $secret, string $account, int $size = 200): string {
        $qrUrl = $this->getQRCodeUrl($secret, $account);
        
        // Use Google Charts API for QR code generation
        $qrImageUrl = sprintf(
            'https://chart.googleapis.com/chart?chs=%dx%d&chld=M|0&cht=qr&chl=%s',
            $size,
            $size,
            urlencode($qrUrl)
        );
        
        return $qrImageUrl;
    }
    
    /**
     * Store TOTP secret for admin
     * 
     * @param int $adminId Admin ID
     * @param string $secret Base32 encoded secret
     * @return bool Success status
     */
    public function storeSecret(int $adminId, string $secret): bool {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO admin_totp_secrets (admin_id, secret, created_at) 
                VALUES (?, ?, NOW())
                ON DUPLICATE KEY UPDATE 
                secret = VALUES(secret), 
                created_at = VALUES(created_at)
            ");
            $stmt->bind_param("is", $adminId, $secret);
            return $stmt->execute();
        } catch (Exception $e) {
            error_log("Error storing TOTP secret: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get TOTP secret for admin
     * 
     * @param int $adminId Admin ID
     * @return string|null Base32 encoded secret or null if not found
     */
    public function getSecret(int $adminId): ?string {
        try {
            $stmt = $this->db->prepare("SELECT secret FROM admin_totp_secrets WHERE admin_id = ?");
            $stmt->bind_param("i", $adminId);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($row = $result->fetch_assoc()) {
                return $row['secret'];
            }
            
            return null;
        } catch (Exception $e) {
            error_log("Error retrieving TOTP secret: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Check if admin has TOTP enabled
     * 
     * @param int $adminId Admin ID
     * @return bool True if TOTP is enabled
     */
    public function isEnabled(int $adminId): bool {
        return $this->getSecret($adminId) !== null;
    }
    
    /**
     * Disable TOTP for admin
     * 
     * @param int $adminId Admin ID
     * @return bool Success status
     */
    public function disable(int $adminId): bool {
        try {
            $stmt = $this->db->prepare("DELETE FROM admin_totp_secrets WHERE admin_id = ?");
            $stmt->bind_param("i", $adminId);
            return $stmt->execute();
        } catch (Exception $e) {
            error_log("Error disabling TOTP: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Base32 encode data
     * 
     * @param string $data Data to encode
     * @return string Base32 encoded string
     */
    private function base32Encode(string $data): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;
        
        for ($i = 0; $i < strlen($data); $i++) {
            $v <<= 8;
            $v += ord($data[$i]);
            $vbits += 8;
            
            while ($vbits >= 5) {
                $vbits -= 5;
                $output .= $alphabet[($v >> $vbits) & 31];
            }
        }
        
        if ($vbits > 0) {
            $v <<= (5 - $vbits);
            $output .= $alphabet[$v & 31];
        }
        
        return $output;
    }
    
    /**
     * Base32 decode data
     * 
     * @param string $data Base32 encoded string
     * @return string Decoded data
     */
    private function base32Decode(string $data): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;
        
        for ($i = 0; $i < strlen($data); $i++) {
            $char = strtoupper($data[$i]);
            $pos = strpos($alphabet, $char);
            
            if ($pos === false) {
                continue;
            }
            
            $v <<= 5;
            $v += $pos;
            $vbits += 5;
            
            if ($vbits >= 8) {
                $vbits -= 8;
                $output .= chr(($v >> $vbits) & 0xFF);
            }
        }
        
        return $output;
    }
    
    /**
     * Generate backup codes for admin
     * 
     * @param int $adminId Admin ID
     * @param int $count Number of backup codes to generate
     * @return array Array of backup codes
     */
    public function generateBackupCodes(int $adminId, int $count = 10): array {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(substr(md5(uniqid('', true)), 0, 8));
        }
        
        // Store hashed backup codes
        $hashedCodes = array_map('password_hash', $codes);
        $this->storeBackupCodes($adminId, $hashedCodes);
        
        return $codes;
    }
    
    /**
     * Store backup codes in database
     * 
     * @param int $adminId Admin ID
     * @param array $hashedCodes Array of hashed backup codes
     * @return bool Success status
     */
    private function storeBackupCodes(int $adminId, array $hashedCodes): bool {
        try {
            // Delete existing backup codes
            $stmt = $this->db->prepare("DELETE FROM admin_backup_codes WHERE admin_id = ?");
            $stmt->bind_param("i", $adminId);
            $stmt->execute();
            
            // Insert new backup codes
            $stmt = $this->db->prepare("INSERT INTO admin_backup_codes (admin_id, code_hash, used) VALUES (?, ?, 0)");
            foreach ($hashedCodes as $hashedCode) {
                $stmt->bind_param("is", $adminId, $hashedCode);
                $stmt->execute();
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Error storing backup codes: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verify backup code
     * 
     * @param int $adminId Admin ID
     * @param string $code Backup code to verify
     * @return bool True if code is valid and unused
     */
    public function verifyBackupCode(int $adminId, string $code): bool {
        try {
            $stmt = $this->db->prepare("SELECT id, code_hash FROM admin_backup_codes WHERE admin_id = ? AND used = 0");
            $stmt->bind_param("i", $adminId);
            $stmt->execute();
            $result = $stmt->get_result();
            
            while ($row = $result->fetch_assoc()) {
                if (password_verify($code, $row['code_hash'])) {
                    // Mark code as used
                    $updateStmt = $this->db->prepare("UPDATE admin_backup_codes SET used = 1 WHERE id = ?");
                    $updateStmt->bind_param("i", $row['id']);
                    $updateStmt->execute();
                    return true;
                }
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Error verifying backup code: " . $e->getMessage());
            return false;
        }
    }
}
