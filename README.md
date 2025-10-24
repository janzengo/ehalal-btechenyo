# E-Halal BTECHenyo Voting System

E-Halal BTECHenyo is a secure web-based voting system designed for Dalubhasaang Politekniko ng Lungsod ng Baliwag. The system enables fair and transparent student council elections through a modern, secure, and user-friendly platform.

## Core Features

### Voter Features
- Two-factor authentication with OTP verification
- Card-based voting interface with real-time validation
- Vote receipt generation and verification
- Mobile-responsive design

### Administrative Features
- Role-based access control (Head Admin/Officers)
- Complete election lifecycle management
- Real-time monitoring and status tracking
- Comprehensive audit logging

## Technology Stack

### Backend
- PHP 7.4+
- MySQL/MariaDB
- Object-Oriented Architecture

### Frontend
- Bootstrap 3
- jQuery 2.2.4
- Chart.js
- SweetAlert2
- Font Awesome 4.7.0

### Server Requirements
- Apache/Nginx web server
- PHP 7.4 or higher
- MySQL 5.7/MariaDB 10.4+
- mod_rewrite enabled
- SMTP server access

## Installation

1. **Database Setup**
   - Create a MySQL database
   - Import schema from `db/schema.sql`

2. **Environment Configuration**
   ```env
   DB_HOST=localhost
   DB_NAME=e-halal
   DB_USERNAME=root
   DB_PASSWORD=

   MAIL_MAILER=smtp
   MAIL_HOST=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=
   MAIL_PASSWORD=
   MAIL_ENCRYPTION=tls
   ```

## Directory Structure
```
e-halal/
├── administrator/         # Administrative interface
│   ├── classes/          # Admin-specific classes
│   ├── includes/         # Admin components
│   └── modals/          # Admin modal forms
├── classes/              # Core system classes
│   ├── Database.php     # Database connection
│   ├── Election.php     # Election management
│   ├── OTPMailer.php    # Email system
│   ├── User.php         # User management
│   └── Votes.php        # Vote processing
├── dist/                 # Distribution files
├── images/              # Uploaded images
├── modals/              # Voter interface modals
└── vendor/              # Composer packages
```

## Security Features
- Two-factor authentication with OTP
- Session management and security
- Audit logging of all activities
- Encrypted vote storage
- Role-based access control
- Rate limiting for OTP requests

## Security Improvement Integrations

The E-Halal BTECHenyo system underwent significant security refactoring to address vulnerabilities and implement industry best practices. Below are the key security improvements implemented:

### 1. Object-Oriented Architecture with Encapsulation

**Previous Implementation (Procedural Approach):**
```php
// Direct database connection exposed globally
$host = 'localhost';
$username = 'root';
$password = 'secret123';
$database = 'e-halal';

$conn = mysqli_connect($host, $username, $password, $database);

// Credentials exposed in every file that needs database access
// No protection of sensitive configuration data
```

**Current Implementation (OOP with Encapsulation):**
```php
class Database {
    private static $instance = null;    
    private $connection;
    private $host;
    private $username;
    private $password;
    private $database;

    private function __construct() {
        $config = config();
        $this->host = $config['DB_HOST'];
        $this->username = $config['DB_USERNAME'];
        $this->password = $config['DB_PASSWORD'];
        $this->database = $config['DB_NAME'];
        
        $this->connection = new mysqli($this->host, $this->username, 
                                       $this->password, $this->database);
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
}
```

**Security Benefits:**
- Database credentials are encapsulated within private properties
- Singleton pattern ensures single connection instance
- Configuration loaded from environment variables (.env file)
- Prevents credential exposure in source code
- Centralized connection management reduces attack surface

### 2. Prepared Statements for SQL Injection Prevention

**Previous Implementation (String Concatenation):**
```php
// Vulnerable to SQL injection attacks
$student_number = $_POST['student_number'];
$query = "SELECT * FROM voters WHERE student_number = '$student_number'";
$result = mysqli_query($conn, $query);

// Attacker could inject: ' OR '1'='1
// Resulting query: SELECT * FROM voters WHERE student_number = '' OR '1'='1'
```

**Current Implementation (PDO Prepared Statements):**
```php
// Protected against SQL injection
$stmt = $this->db->prepare("SELECT * FROM voters WHERE student_number = ?");
$stmt->bind_param("s", $student_number);
$stmt->execute();
$result = $stmt->get_result();

// User input is properly escaped and parameterized
// Malicious input is treated as literal string, not executable code
```

**Security Benefits:**
- Complete protection against SQL injection attacks
- Input is automatically escaped and sanitized
- Query structure separated from user data
- Type-safe parameter binding (string, integer, etc.)
- All database queries throughout the system use prepared statements

### 3. Secure Session Management with Custom Handler

**Previous Implementation (Default PHP Sessions):**
```php
// Basic session with no security measures
session_start();
$_SESSION['voter_id'] = $voter_id;
$_SESSION['student_number'] = $student_number;

// Vulnerable to:
// - Session fixation attacks
// - Session hijacking
// - No session regeneration
// - No timeout management
```

**Current Implementation (Custom Session Handler):**
```php
class CustomSessionHandler {
    private static $instance = null;
    
    private function __construct() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
    
    public function setSession($key, $value) {
        $_SESSION[$key] = $value;
    }
    
    public function regenerateSession() {
        session_regenerate_id(true);
    }
}

// Usage in User class
public function setSession() {
    $this->session->setSession('voter', $this->id);
    $this->session->setSession('student_number', $this->student_number);
    session_regenerate_id(true); // Prevents session fixation
    
    $this->logger->generateLog('voters', date('Y-m-d H:i:s'), 
                               $this->student_number, 
                               ['action' => 'Session created']);
}
```

**Security Benefits:**
- Session ID regeneration after authentication prevents fixation attacks
- Centralized session management with consistent security policies
- Automatic session logging for audit trails
- Proper session destruction on logout
- Singleton pattern prevents multiple session handlers

### 4. Sensitive Data Protection in Email Operations

**Previous Implementation (Hardcoded Credentials):**
```php
// SMTP credentials exposed in code
$mail->Host = 'smtp.gmail.com';
$mail->Username = 'admin@example.com';
$mail->Password = 'hardcoded_password123';
$mail->Port = 587;

// Credentials visible in version control
// No separation of configuration from code
```

**Current Implementation (Environment-Based Configuration):**
```php
class OTPMailer {
    private $mail_config;
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->mail_config = mail_config();
    }
    
    public function sendOTPEmail($student_number, $email, $otp, $name = '') {
        $mail = new PHPMailer(true);
        
        // Credentials loaded from environment variables
        $mail->Host = $_ENV['MAIL_HOST'];
        $mail->Username = $_ENV['MAIL_USERNAME'];
        $mail->Password = $_ENV['MAIL_PASSWORD'];
        $mail->SMTPSecure = $_ENV['MAIL_ENCRYPTION'];
        $mail->Port = $_ENV['MAIL_PORT'];
    }
}
```

**Security Benefits:**
- SMTP credentials stored in .env file (excluded from version control)
- No hardcoded sensitive information in source code
- Easy credential rotation without code changes
- Encapsulation of email operations within dedicated class
- Separation of concerns between configuration and business logic

### Summary

These security improvements transformed the E-Halal BTECHenyo system from a procedural codebase with exposed credentials and SQL injection vulnerabilities into a secure, object-oriented application following modern security best practices. The refactoring provides:

- **Overall code quality and security overhaul** by leveraging the power of Object Oriented Programming
- **Secure by default** configuration management
- **Audit trail** for all critical operations
- **Protection against common web vulnerabilities** (SQL injection, session attacks, credential exposure)

