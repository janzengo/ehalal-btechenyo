<?php
declare(strict_types=1);

require_once __DIR__ . '/../../init.php';
require_once __DIR__ . '/../classes/Admin.php';
require_once __DIR__ . '/../classes/Session.php';
require_once __DIR__ . '/../classes/Logger.php';
require_once __DIR__ . '/../classes/Elections.php';
require_once __DIR__ . '/../../classes/TOTP.php';

// Initialize classes
$admin = Admin::getInstance();
$session = Session::getInstance();
$logger = AdminLogger::getInstance();
$elections = Elections::getInstance();
$totp = new TOTP();

// Check if we have temporary admin data
$tempUsername = $session->getSession('temp_admin_username');
$tempAdminData = $session->getSession('temp_admin_data');

if (!$tempUsername || !$tempAdminData) {
    $session->setError('No pending authentication found. Please login again.');
    header('Location: ' . BASE_URL . 'administrator/');
    exit();
}

// Handle TOTP verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $totpCode = $_POST['totp_code'] ?? '';
    $backupCode = $_POST['backup_code'] ?? '';
    
    if (empty($totpCode) && empty($backupCode)) {
        $session->setError('Please enter a TOTP code or backup code.');
        header('Location: totp_verify.php');
        exit();
    }
    
    try {
        $adminId = $tempAdminData['id'];
        $secret = $totp->getSecret($adminId);
        
        if (!$secret) {
            throw new Exception('TOTP is not configured for this account. Please contact support.');
        }
        
        $isValid = false;
        $usedBackup = false;
        
        // Try TOTP code first
        if (!empty($totpCode)) {
            $isValid = $totp->verifyCode($secret, $totpCode);
        }
        
        // Try backup code if TOTP failed
        if (!$isValid && !empty($backupCode)) {
            $isValid = $totp->verifyBackupCode($adminId, $backupCode);
            $usedBackup = true;
        }
        
        if ($isValid) {
            // Complete login
            if ($admin->completeLogin($tempUsername)) {
                // Log the successful login
                $logger->logAdminAction(
                    $tempAdminData['username'], 
                    $tempAdminData['role'], 
                    'Logged in successfully with ' . ($usedBackup ? 'backup code' : 'TOTP')
                );
                
                // Clean up temporary data
                $session->unsetSession('temp_admin_username');
                $session->unsetSession('temp_admin_data');
                $session->setSuccess('Login successful');
                
                // Get current election status and determine redirect URL
                $current_status = $elections->getCurrentStatus();
                $base_url = BASE_URL . 'administrator/';
                
                switch($current_status) {
                    case 'setup':
                        $redirect_url = $base_url . 'setup';
                        break;
                    case 'pending':
                        $redirect_url = $base_url . 'configure';
                        break;
                    case 'active':
                        $redirect_url = $base_url . 'home';
                        break;
                    case 'completed':
                        $redirect_url = $base_url . 'completed';
                        break;
                    default:
                        $redirect_url = $base_url . 'home';
                }
                
                if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
                    echo json_encode(['success' => true, 'redirect' => $redirect_url]);
                    exit();
                }
                
                header('Location: ' . $redirect_url);
                exit();
            } else {
                throw new Exception('Failed to complete login.');
            }
        } else {
            throw new Exception('Invalid TOTP code or backup code.');
        }
        
    } catch (Exception $e) {
        $session->setError($e->getMessage());
        
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            exit();
        }
        
        header('Location: totp_verify.php');
        exit();
    }
}

// Handle cancel request
if (isset($_GET['cancel'])) {
    $session->unsetSession('temp_admin_username');
    $session->unsetSession('temp_admin_data');
    header('Location: ' . BASE_URL . 'administrator/');
    exit();
}

echo $view->renderHeader();
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>E-Halal | TOTP Verification</title>
    <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
    
    <!-- Bootstrap -->
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>node_modules/bootstrap/dist/css/bootstrap.min.css">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>plugins/font-awesome/css/all.min.css">
    <!-- AdminLTE -->
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>dist/css/AdminLTE.css">
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>dist/css/skins/_all-skins.min.css">
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>dist/css/custom.css">
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>dist/css/login.css">
    
    <style>
        .totp-container {
            max-width: 400px;
            margin: 0 auto;
            margin-top: 50px;
        }
        .totp-input {
            letter-spacing: 0.5rem;
            font-size: 1.5rem;
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            border: 2px solid #ddd;
            background-color: #f8f9fa;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
        }
        .backup-input {
            font-family: monospace;
            letter-spacing: 0.2rem;
        }
        .auth-tabs {
            margin-bottom: 20px;
        }
        .tab-content {
            padding: 20px 0;
        }
        .help-text {
            font-size: 0.9em;
            color: #666;
            margin-top: 10px;
        }
    </style>
</head>

<body class="hold-transition login-page">
    <div class="inner-body">
        <div class="login-box">
            <div class="login-logo-container">
                <img src="<?php echo BASE_URL; ?>images/login.jpg" alt="">
                <h1><span>E-HALAL</span> <br> BTECHenyo</h1>
            </div>
            <p class="text-center text-smaller">TWO-FACTOR AUTHENTICATION<br>ADMIN PORTAL</p>
            
            <?php if ($session->hasSuccess()): ?>
                <div class="alert alert-success alert-dismissible">
                    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                    <h4><i class="icon fa fa-check"></i> Success!</h4>
                    <?php echo $session->getSuccess(); ?>
                </div>
                <?php $session->clearSuccess(); ?>
            <?php endif; ?>

            <?php if ($session->hasError()): ?>
                <div class="alert alert-danger alert-dismissible">
                    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                    <h4><i class="icon fa fa-ban"></i> Error!</h4>
                    <?php echo $session->getError(); ?>
                </div>
                <?php $session->clearError(); ?>
            <?php endif; ?>
            
            <div class="login-box-body">
                <div class="text-center mb-3">
                    <h4>Two-Factor Authentication</h4>
                    <p class="text-muted">Welcome, <strong><?php echo htmlspecialchars($tempAdminData['firstname'] . ' ' . $tempAdminData['lastname']); ?></strong></p>
                    <p class="text-sm">Enter your 6-digit TOTP code or backup code to continue</p>
                </div>
                
                <!-- Auth Method Tabs -->
                <ul class="nav nav-tabs auth-tabs" role="tablist">
                    <li role="presentation" class="active">
                        <a href="#totp-tab" aria-controls="totp-tab" role="tab" data-toggle="tab">
                            <i class="fa fa-mobile"></i> TOTP Code
                        </a>
                    </li>
                    <li role="presentation">
                        <a href="#backup-tab" aria-controls="backup-tab" role="tab" data-toggle="tab">
                            <i class="fa fa-key"></i> Backup Code
                        </a>
                    </li>
                </ul>
                
                <div class="tab-content">
                    <!-- TOTP Code Tab -->
                    <div role="tabpanel" class="tab-pane active" id="totp-tab">
                        <form method="POST" id="totpForm">
                            <div class="form-group">
                                <label for="totp_code">Enter 6-digit code from your authenticator app:</label>
                                <input type="text" class="form-control totp-input" id="totp_code" name="totp_code" 
                                       placeholder="123456" maxlength="6" autocomplete="off" required>
                                <div class="help-text">
                                    <i class="fa fa-info-circle"></i> 
                                    Open Google Authenticator and enter the current 6-digit code
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-xs-12">
                                    <button type="submit" class="btn btn-primary btn-block btn-flat">
                                        <i class="fa fa-sign-in"></i> Verify & Login
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                    
                    <!-- Backup Code Tab -->
                    <div role="tabpanel" class="tab-pane" id="backup-tab">
                        <form method="POST" id="backupForm">
                            <div class="form-group">
                                <label for="backup_code">Enter your backup code:</label>
                                <input type="text" class="form-control backup-input" id="backup_code" name="backup_code" 
                                       placeholder="A1B2C3D4" autocomplete="off">
                                <div class="help-text">
                                    <i class="fa fa-info-circle"></i> 
                                    Use one of your saved backup codes (8 characters)
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-xs-12">
                                    <button type="submit" class="btn btn-warning btn-block btn-flat">
                                        <i class="fa fa-key"></i> Use Backup Code
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
                
                <hr>
                <div class="text-center">
                    <a href="?cancel=1" class="btn btn-outline-secondary btn-sm">
                        <i class="fa fa-arrow-left"></i> Back to Login
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- jQuery -->
    <script src="<?php echo BASE_URL; ?>node_modules/jquery/dist/jquery.min.js"></script>
    <!-- Bootstrap -->
    <script src="<?php echo BASE_URL; ?>node_modules/bootstrap/dist/js/bootstrap.min.js"></script>
    <!-- SweetAlert2 -->
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    
    <script>
        $(document).ready(function() {
            // Auto-focus on TOTP input
            $('#totp_code').focus();
            
            // Format TOTP input
            $('#totp_code').on('input', function() {
                this.value = this.value.replace(/[^0-9]/g, '');
            });
            
            // Format backup code input
            $('#backup_code').on('input', function() {
                this.value = this.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
            });
            
            // Handle form submission
            $('#totpForm, #backupForm').on('submit', function(e) {
                e.preventDefault();
                var form = $(this);
                var btn = form.find('button[type="submit"]');
                var originalText = btn.html();
                
                // Show loading state
                btn.prop('disabled', true);
                btn.html('<i class="fa fa-spinner fa-spin"></i> Verifying...');
                
                // Submit form via AJAX
                $.ajax({
                    url: form.attr('action'),
                    type: 'POST',
                    data: form.serialize(),
                    dataType: 'json',
                    success: function(response) {
                        if (response.success) {
                            Swal.fire({
                                icon: 'success',
                                title: 'Authentication Successful!',
                                text: 'Redirecting to admin panel...',
                                timer: 2000,
                                showConfirmButton: false,
                                allowOutsideClick: false
                            }).then(function() {
                                window.location.href = response.redirect;
                            });
                        } else {
                            Swal.fire({
                                icon: 'error',
                                title: 'Authentication Failed',
                                text: response.message
                            });
                            
                            // Reset button
                            btn.prop('disabled', false);
                            btn.html(originalText);
                        }
                    },
                    error: function() {
                        Swal.fire({
                            icon: 'error',
                            title: 'Error',
                            text: 'An error occurred. Please try again.'
                        });
                        
                        // Reset button
                        btn.prop('disabled', false);
                        btn.html(originalText);
                    }
                });
            });
            
            // Switch to backup tab if TOTP fails
            $('#totpForm').on('submit', function() {
                setTimeout(function() {
                    if ($('.alert-danger').length > 0) {
                        $('a[href="#backup-tab"]').tab('show');
                    }
                }, 1000);
            });
        });
    </script>
</body>
</html>
