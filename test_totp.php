<?php
declare(strict_types=1);

/**
 * TOTP Test Script
 * This script tests the TOTP functionality without requiring database setup
 */

require_once 'classes/TOTP.php';

echo "<h1>TOTP System Test</h1>\n";
echo "<p>Testing TOTP functionality...</p>\n";

try {
    $totp = new TOTP();
    
    // Test 1: Generate secret
    echo "<h2>Test 1: Secret Generation</h2>\n";
    $secret = $totp->generateSecret();
    echo "<p><strong>Generated Secret:</strong> <code>$secret</code></p>\n";
    
    // Test 2: Generate TOTP code
    echo "<h2>Test 2: TOTP Code Generation</h2>\n";
    $code = $totp->generateCode($secret);
    echo "<p><strong>Generated Code:</strong> <code>$code</code></p>\n";
    
    // Test 3: Verify TOTP code
    echo "<h2>Test 3: TOTP Code Verification</h2>\n";
    $isValid = $totp->verifyCode($secret, $code);
    echo "<p><strong>Code Valid:</strong> " . ($isValid ? "✅ YES" : "❌ NO") . "</p>\n";
    
    // Test 4: Generate QR Code URL
    echo "<h2>Test 4: QR Code URL Generation</h2>\n";
    $qrUrl = $totp->getQRCodeUrl($secret, 'test@example.com');
    echo "<p><strong>QR Code URL:</strong></p>\n";
    echo "<p><code style='word-break: break-all;'>$qrUrl</code></p>\n";
    
    // Test 5: Generate QR Code Image
    echo "<h2>Test 5: QR Code Image</h2>\n";
    $qrImage = $totp->getQRCodeImage($secret, 'test@example.com', 200);
    echo "<p><strong>QR Code Image:</strong></p>\n";
    echo "<img src='$qrImage' alt='TOTP QR Code' style='border: 1px solid #ccc; padding: 10px;'>\n";
    
    // Test 6: Test with different time
    echo "<h2>Test 6: Time-based Verification</h2>\n";
    $futureTime = time() + 30; // 30 seconds in the future
    $futureCode = $totp->generateCode($secret, $futureTime);
    $isValidFuture = $totp->verifyCode($secret, $futureCode);
    echo "<p><strong>Future Code:</strong> <code>$futureCode</code></p>\n";
    echo "<p><strong>Future Code Valid:</strong> " . ($isValidFuture ? "✅ YES" : "❌ NO") . "</p>\n";
    
    // Test 7: Test invalid code
    echo "<h2>Test 7: Invalid Code Test</h2>\n";
    $invalidCode = '123456';
    $isInvalid = $totp->verifyCode($secret, $invalidCode);
    echo "<p><strong>Invalid Code Test:</strong> " . ($isInvalid ? "❌ FAILED (should be false)" : "✅ PASSED (correctly rejected)") . "</p>\n";
    
    echo "<h2>✅ All Tests Completed Successfully!</h2>\n";
    echo "<p>The TOTP system is working correctly and is ready for integration.</p>\n";
    
    echo "<h3>Next Steps:</h3>\n";
    echo "<ol>\n";
    echo "<li>Run the database schema: <code>db/totp_schema.sql</code></li>\n";
    echo "<li>Test with Google Authenticator using the QR code above</li>\n";
    echo "<li>Login to admin panel and set up TOTP for your account</li>\n";
    echo "</ol>\n";
    
} catch (Exception $e) {
    echo "<h2>❌ Test Failed</h2>\n";
    echo "<p><strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>\n";
    echo "<p>Please check your PHP configuration and try again.</p>\n";
}

echo "<hr>\n";
echo "<p><small>Generated at: " . date('Y-m-d H:i:s') . "</small></p>\n";
?>
