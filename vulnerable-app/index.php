<?php
/**
 * ============================================================
 *  THE LEAKY BRIDGE — Vulnerable Web Application (Lab Only)
 * ============================================================
 *
 *  WARNING: This code is INTENTIONALLY VULNERABLE.
 *  It is designed purely for educational purposes in an
 *  isolated lab environment. NEVER deploy this in production.
 *
 *  Vulnerability present: Local File Inclusion (LFI)
 *  CVE Reference: CWE-22 (Path Traversal)
 * ============================================================
 */

// ─── Fake "secure" config loaded at startup ─────────────────
// A developer hard-coded credentials and forgot to remove them.
// This simulates the "developer mistake" scenario.
define('APP_VERSION', '2.3.1');
define('APP_NAME',    'CorpIntranet Portal');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= APP_NAME ?> – File Viewer</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 40px 20px;
        }
        header {
            width: 100%;
            max-width: 800px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 16px;
            margin-bottom: 32px;
        }
        header h1 { font-size: 1.4rem; color: #58a6ff; }
        header p  { font-size: 0.85rem; color: #8b949e; margin-top: 4px; }

        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 24px;
            width: 100%;
            max-width: 800px;
            margin-bottom: 24px;
        }
        .card h2 { font-size: 1rem; color: #f0883e; margin-bottom: 12px; }

        form { display: flex; gap: 10px; flex-wrap: wrap; }
        input[type="text"] {
            flex: 1;
            padding: 10px 14px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-family: monospace;
            font-size: 0.9rem;
        }
        button {
            padding: 10px 20px;
            background: #238636;
            border: none;
            border-radius: 6px;
            color: #fff;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.2s;
        }
        button:hover { background: #2ea043; }

        pre {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 0.85rem;
            line-height: 1.6;
            color: #e6edf3;
            margin-top: 16px;
        }
        .error { color: #f85149; margin-top: 12px; font-size: 0.9rem; }
        .hint  { color: #8b949e; font-size: 0.8rem; margin-top: 8px; }
        footer { color: #484f58; font-size: 0.75rem; margin-top: 40px; }
    </style>
</head>
<body>

<header>
    <h1>📁 <?= APP_NAME ?> – Internal Document Viewer</h1>
    <p>v<?= APP_VERSION ?> | Internal use only | IT Department</p>
</header>

<div class="card">
    <h2>📄 View System Documentation</h2>
    <p class="hint">Enter a document filename from the /docs directory to preview its contents.</p>

    <form method="GET" action="">
        <input
            type="text"
            name="file"
            placeholder="e.g., welcome.txt"
            value="<?= htmlspecialchars($_GET['file'] ?? '') ?>"
        >
        <button type="submit">View File</button>
    </form>

    <?php
    // ─── VULNERABILITY: Unvalidated user input passed to file functions ───────
    // The developer "tried" to restrict paths but did it incorrectly.
    // There is NO real sanitization — path traversal (../../) still works.
    if (isset($_GET['file']) && !empty($_GET['file'])) {
        $filename = $_GET['file'];

        // ❌ BROKEN FILTER: Only checks for a naive substring — bypassable!
        // e.g., file=....//....//....//etc/passwd bypasses the simple check
        if (strpos($filename, '../') !== false) {
            echo '<p class="error">⚠ Access denied: Directory traversal detected.</p>';
        } else {
            // ❌ BASE PATH is not enforced — attacker can use absolute paths
            // or encoded sequences like ..%2F to escape
            $base_path = '/var/www/html/docs/';
            $full_path = $base_path . $filename;

            // ❌ No realpath() check — symlinks and absolute paths accepted
            if (file_exists($full_path)) {
                $content = file_get_contents($full_path);
                echo '<pre>' . htmlspecialchars($content) . '</pre>';
            } else {
                echo '<p class="error">❌ File not found: ' . htmlspecialchars($full_path) . '</p>';
            }
        }
    }
    ?>
</div>

<div class="card">
    <h2>🔗 Quick Links</h2>
    <ul style="list-style:none; display:flex; gap:12px; flex-wrap:wrap;">
        <li><a href="?file=welcome.txt"       style="color:#58a6ff;">welcome.txt</a></li>
        <li><a href="?file=network-map.txt"   style="color:#58a6ff;">network-map.txt</a></li>
        <li><a href="?file=server-info.txt"   style="color:#58a6ff;">server-info.txt</a></li>
        <li><a href="?file=maintenance.txt"   style="color:#58a6ff;">maintenance.txt</a></li>
    </ul>
</div>

<footer>CorpIntranet Portal <?= date('Y') ?> – Confidential – Internal Network Only</footer>

</body>
</html>
