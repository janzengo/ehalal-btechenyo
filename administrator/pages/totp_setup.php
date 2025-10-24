<?php
declare(strict_types=1);

require_once __DIR__ . '/../../init.php';
require_once __DIR__ . '/../classes/Admin.php';
require_once __DIR__ . '/../classes/Session.php';
require_once __DIR__ . '/../classes/Logger.php';
require_once __DIR__ . '/../classes/View.php';
require_once __DIR__ . '/../../classes/TOTP.php';
require_once __DIR__ . '/../../classes/Database.php';
require_once __DIR__ . '/../includes/access_control.php';

// Initialize classes
$admin = Admin::getInstance();
$session = Session::getInstance();
$logger = AdminLogger::getInstance();
$view = View::getInstance();
$totp = new TOTP();

// Check if admin is logged in
if (!$admin->isLoggedIn()) {
    header('Location: ' . BASE_URL . 'administrator/');
    exit();
}

$currentAdmin = $admin->getAdminData();
$adminId = $currentAdmin['id'];

// Handle TOTP setup/disable requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    try {
        if ($action === 'setup') {
            // Generate new TOTP secret
            $secret = $totp->generateSecret();
            $totp->storeSecret($adminId, $secret);
            
            // Generate backup codes
            $backupCodes = $totp->generateBackupCodes($adminId);
            
            $session->setSuccess('TOTP setup initiated. Please scan the QR code with your authenticator app.');
            
        } elseif ($action === 'verify') {
            $code = $_POST['totp_code'] ?? '';
            $secret = $totp->getSecret($adminId);
            
            if (!$secret) {
                throw new Exception('No TOTP secret found. Please start setup again.');
            }
            
            if ($totp->verifyCode($secret, $code)) {
                // Update admin table to mark TOTP as enabled
                $db = Database::getInstance();
                $stmt = $db->prepare("UPDATE admin SET totp_enabled = 1 WHERE id = ?");
                $stmt->bind_param("i", $adminId);
                $stmt->execute();
                
                $logger->logAdminAction($currentAdmin['username'], $currentAdmin['role'], 'TOTP enabled successfully');
                $session->setSuccess('TOTP has been successfully enabled!');
                
                header('Location: ' . BASE_URL . 'administrator/pages/totp_setup.php?success=1');
                exit();
            } else {
                throw new Exception('Invalid TOTP code. Please try again.');
            }
            
        } elseif ($action === 'disable') {
            $confirmCode = $_POST['confirm_code'] ?? '';
            $secret = $totp->getSecret($adminId);
            
            if (!$secret) {
                throw new Exception('TOTP is not enabled.');
            }
            
            // Verify with TOTP or backup code
            $isValid = $totp->verifyCode($secret, $confirmCode) || $totp->verifyBackupCode($adminId, $confirmCode);
            
            if ($isValid) {
                $totp->disable($adminId);
                
                // Update admin table
                $db = Database::getInstance();
                $stmt = $db->prepare("UPDATE admin SET totp_enabled = 0 WHERE id = ?");
                $stmt->bind_param("i", $adminId);
                $stmt->execute();
                
                $logger->logAdminAction($currentAdmin['username'], $currentAdmin['role'], 'TOTP disabled');
                $session->setSuccess('TOTP has been disabled successfully.');
                
                header('Location: ' . BASE_URL . 'administrator/pages/totp_setup.php');
                exit();
            } else {
                throw new Exception('Invalid verification code.');
            }
        }
    } catch (Exception $e) {
        $session->setError($e->getMessage());
    }
}

// Get current TOTP status
$isEnabled = $totp->isEnabled($adminId);
$secret = $totp->getSecret($adminId);
$qrCodeUrl = $secret ? $totp->getQRCodeImage($secret, $currentAdmin['username']) : null;

// Get backup codes if TOTP is enabled
$backupCodes = [];
if ($isEnabled) {
    // Note: We don't show backup codes after initial setup for security
    // They should be saved by the user during setup
}

echo $view->renderHeader();
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>E-Halal | TOTP Setup</title>
    <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
    
    <!-- Bootstrap -->
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>node_modules/bootstrap/dist/css/bootstrap.min.css">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>plugins/font-awesome/css/all.min.css">
    <!-- AdminLTE -->
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>dist/css/AdminLTE.css">
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>dist/css/skins/_all-skins.min.css">
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>dist/css/custom.css">
    
    <style>
        .totp-container {
            max-width: 600px;
            margin: 0 auto;
        }
        .qr-code {
            text-align: center;
            margin: 20px 0;
        }
        .qr-code img {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 10px;
            background: white;
        }
        .backup-codes {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }
        .backup-codes code {
            display: block;
            margin: 5px 0;
            padding: 5px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
        }
        .step {
            margin: 20px 0;
            padding: 15px;
            border-left: 4px solid #007bff;
            background: #f8f9fa;
        }
        .danger-zone {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
    </style>
</head>

<body class="hold-transition skin-blue sidebar-mini">
    <div class="wrapper">
        <?php include __DIR__ . '/../includes/navbar.php'; ?>
        <?php include __DIR__ . '/../includes/sidebar.php'; ?>

        <div class="content-wrapper">
            <section class="content-header">
                <h1>
                    Two-Factor Authentication (TOTP)
                    <small>Setup Google Authenticator</small>
                </h1>
                <ol class="breadcrumb">
                    <li><a href="<?php echo BASE_URL; ?>administrator/"><i class="fa fa-dashboard"></i> Home</a></li>
                    <li class="active">TOTP Setup</li>
                </ol>
            </section>

            <section class="content">
                <div class="totp-container">
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

                    <?php if (!$isEnabled): ?>
                        <!-- TOTP Setup -->
                        <div class="box box-primary">
                            <div class="box-header with-border">
                                <h3 class="box-title">Enable Two-Factor Authentication</h3>
                            </div>
                            <div class="box-body">
                                <?php if (!$secret): ?>
                                    <!-- Initial Setup -->
                                    <div class="step">
                                        <h4><i class="fa fa-shield"></i> Step 1: Start Setup</h4>
                                        <p>Click the button below to generate your TOTP secret and QR code.</p>
                                        <form method="POST">
                                            <input type="hidden" name="action" value="setup">
                                            <button type="submit" class="btn btn-primary">
                                                <i class="fa fa-qrcode"></i> Generate QR Code
                                            </button>
                                        </form>
                                    </div>
                                <?php else: ?>
                                    <!-- QR Code Display -->
                                    <div class="step">
                                        <h4><i class="fa fa-qrcode"></i> Step 1: Scan QR Code</h4>
                                        <p>Open Google Authenticator (or any TOTP app) on your phone and scan this QR code:</p>
                                        <div class="qr-code">
                                            <img src="<?php echo $qrCodeUrl; ?>" alt="TOTP QR Code">
                                        </div>
                                        <p class="text-muted">
                                            <strong>Manual Entry:</strong> If you can't scan the QR code, manually enter this secret key:<br>
                                            <code><?php echo $secret; ?></code>
                                        </p>
                                    </div>

                                    <div class="step">
                                        <h4><i class="fa fa-check-circle"></i> Step 2: Verify Setup</h4>
                                        <p>Enter the 6-digit code from your authenticator app to complete setup:</p>
                                        <form method="POST" class="form-inline">
                                            <input type="hidden" name="action" value="verify">
                                            <div class="form-group">
                                                <input type="text" name="totp_code" class="form-control" 
                                                       placeholder="123456" maxlength="6" pattern="[0-9]{6}" 
                                                       style="width: 120px; text-align: center; font-size: 18px; letter-spacing: 2px;" required>
                                            </div>
                                            <button type="submit" class="btn btn-success">
                                                <i class="fa fa-check"></i> Verify & Enable
                                            </button>
                                        </form>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>

                    <?php else: ?>
                        <!-- TOTP Already Enabled -->
                        <div class="box box-success">
                            <div class="box-header with-border">
                                <h3 class="box-title">
                                    <i class="fa fa-shield text-green"></i> Two-Factor Authentication Enabled
                                </h3>
                            </div>
                            <div class="box-body">
                                <div class="alert alert-success">
                                    <h4><i class="fa fa-check"></i> TOTP is Active</h4>
                                    <p>Your account is protected with Two-Factor Authentication using Google Authenticator.</p>
                                </div>

                                <div class="step danger-zone">
                                    <h4><i class="fa fa-warning text-red"></i> Disable TOTP</h4>
                                    <p><strong>Warning:</strong> Disabling TOTP will reduce your account security. You'll need to enter a valid TOTP code or backup code to disable it.</p>
                                    
                                    <button type="button" class="btn btn-danger" data-toggle="modal" data-target="#disableModal">
                                        <i class="fa fa-times"></i> Disable TOTP
                                    </button>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- Help Section -->
                    <div class="box box-info">
                        <div class="box-header with-border">
                            <h3 class="box-title"><i class="fa fa-question-circle"></i> Help & Information</h3>
                        </div>
                        <div class="box-body">
                            <h4>What is TOTP?</h4>
                            <p>TOTP (Time-based One-Time Password) is a security standard that generates time-sensitive codes. It's used by Google Authenticator, Authy, and other authenticator apps.</p>
                            
                            <h4>How to use:</h4>
                            <ol>
                                <li>Install Google Authenticator (or similar app) on your phone</li>
                                <li>Scan the QR code or manually enter the secret key</li>
                                <li>Enter the 6-digit code when logging in</li>
                            </ol>
                            
                            <h4>Backup Codes</h4>
                            <p>During setup, you'll receive backup codes. Save these in a secure location - they can be used if you lose access to your authenticator app.</p>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    </div>

    <!-- Disable TOTP Modal -->
    <div class="modal fade" id="disableModal" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Disable Two-Factor Authentication</h4>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <div class="alert alert-warning">
                            <strong>Warning:</strong> This will disable TOTP for your account and reduce security.
                        </div>
                        <p>To disable TOTP, enter a valid 6-digit code from your authenticator app or a backup code:</p>
                        <div class="form-group">
                            <label for="confirm_code">Verification Code:</label>
                            <input type="text" name="confirm_code" id="confirm_code" class="form-control" 
                                   placeholder="123456 or backup code" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                        <button type="submit" name="action" value="disable" class="btn btn-danger">
                            <i class="fa fa-times"></i> Disable TOTP
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- jQuery -->
    <script src="<?php echo BASE_URL; ?>node_modules/jquery/dist/jquery.min.js"></script>
    <!-- Bootstrap -->
    <script src="<?php echo BASE_URL; ?>node_modules/bootstrap/dist/js/bootstrap.min.js"></script>
    <!-- AdminLTE -->
    <script src="<?php echo BASE_URL; ?>dist/js/adminlte.min.js"></script>

    <script>
        $(document).ready(function() {
            // Auto-focus on TOTP code input
            $('input[name="totp_code"]').focus();
            
            // Format TOTP code input
            $('input[name="totp_code"]').on('input', function() {
                this.value = this.value.replace(/[^0-9]/g, '');
            });
        });
    </script>
</body>
</html>
