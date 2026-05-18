<?php
/**
 * ============================================================
 *  defense/fixed_index.php — PATCHED Version of the Web App
 *  Project: The Leaky Bridge – Hybrid Cloud Attack Vector
 * ============================================================
 *
 *  This file shows the SECURE version of index.php.
 *  Compare with vulnerable-app/index.php to understand each fix.
 *
 *  Vulnerabilities Fixed:
 *  ✅ FIX 1: Input validation with allowlist (whitelist)
 *  ✅ FIX 2: realpath() + directory confinement check
 *  ✅ FIX 3: Removed user input from file_exists() path
 *  ✅ FIX 4: Specific error messages removed (no info leakage)
 *  ✅ FIX 5: Logging of suspicious requests
 * ============================================================
 */

// ── SECURE CONFIGURATION ────────────────────────────────────

// ✅ FIX 1: Define a strict allowlist of permitted filenames.
//    Only these files can be viewed — no user-controlled paths.
const ALLOWED_FILES = [
    'welcome.txt',
    'network-map.txt',
    'server-info.txt',
    'maintenance.txt',
];

// ✅ FIX 2: Define the base directory and resolve it absolutely.
$base_dir = realpath('/var/www/html/docs');

// Guard: if the base directory doesn't exist, fail safely
if ($base_dir === false) {
    error_log("[SECURITY] Base docs directory not found — refusing all requests");
    die("Service temporarily unavailable.");
}

$content = null;
$error   = null;

if (isset($_GET['file']) && !empty($_GET['file'])) {
    $requested = $_GET['file'];

    // ✅ FIX 3: Allowlist check — reject anything not in the list
    if (!in_array($requested, ALLOWED_FILES, true)) {
        // ✅ FIX 5: Log the suspicious request for SOC review
        error_log(sprintf(
            "[SECURITY] Suspicious file request: '%s' from IP: %s | UA: %s",
            $requested,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ));
        $error = "Requested document is not available.";  // Vague on purpose
    } else {
        // ✅ FIX 4: Construct path only after allowlist validation
        $full_path = $base_dir . DIRECTORY_SEPARATOR . $requested;

        // ✅ FIX 2: Use realpath() to resolve symlinks and canonicalize
        $real_path = realpath($full_path);

        // ✅ FIX 2: Verify the resolved path is still inside base_dir
        //    This prevents symlink attacks and any traversal that slips through
        if ($real_path === false || strpos($real_path, $base_dir) !== 0) {
            error_log(sprintf(
                "[SECURITY] Path traversal attempt blocked: '%s' resolved to '%s'",
                $requested,
                $real_path ?: 'INVALID'
            ));
            $error = "Access denied.";
        } else {
            // Safe to read
            $content = file_get_contents($real_path);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CorpIntranet Portal – Document Viewer (Secure)</title>
    <!-- ... same styling ... -->
</head>
<body>
<!-- ... same UI with content/error rendering ... -->
<?php if ($content): ?>
    <pre><?= htmlspecialchars($content, ENT_QUOTES, 'UTF-8') ?></pre>
<?php elseif ($error): ?>
    <p class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
<?php endif; ?>
</body>
</html>

<!--
═══════════════════════════════════════════════════════════════
  SECURITY ANALYSIS: What Changed and Why
═══════════════════════════════════════════════════════════════

  VULNERABLE CODE (index.php):
  ─────────────────────────────
  $filename  = $_GET['file'];                    // No validation
  $full_path = '/var/www/html/docs/' . $filename; // String concat
  if (file_exists($full_path)) {                 // No realpath check
      echo file_get_contents($full_path);        // Direct read
  }

  ATTACK PAYLOAD that worked:
    ?file=/home/ubuntu/.aws/credentials
    ?file=/etc/passwd
    ?file=/proc/self/environ

  SECURE CODE (this file):
  ─────────────────────────
  1. in_array($requested, ALLOWED_FILES, true)
     → Only files explicitly listed can be requested.
       Anything else is rejected BEFORE touching the filesystem.

  2. realpath($full_path)
     → Resolves all symlinks, '..' sequences, and encoded
       characters to an absolute canonical path.

  3. strpos($real_path, $base_dir) !== 0
     → Even if somehow a file slips through, this final check
       ensures the resolved path starts with our trusted dir.
       '/var/www/html/docs/welcome.txt' — ALLOWED
       '/home/ubuntu/.aws/credentials'  — BLOCKED

  4. error_log() instead of revealing errors to the user
     → Attackers learn nothing about the system structure.

  ADDITIONAL HARDENING (outside this file):
  ─────────────────────────────────────────
  • PHP: open_basedir = /var/www/html — kernel-level restriction
  • Apache: <Directory /var/www/html> Options -Indexes
  • Linux: Web server runs as unprivileged user (www-data)
  • AWS:  No credentials on disk — use IAM Roles for EC2 instead
═══════════════════════════════════════════════════════════════
-->
