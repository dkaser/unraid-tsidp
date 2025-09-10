#!/usr/bin/env php
<?php

require_once __DIR__ . '/functions.php';

$issuer = file_get_contents('/var/run/tsidp-issuer');
if ( ! $issuer) {
    logMessage("Issuer not found in /var/run/tsidp-issuer", 'ERROR');
    exit(1);
}
$issuer = trim($issuer);
if (strpos($issuer, 'https://') !== 0) {
    logMessage("Invalid issuer format in /var/run/tsidp-issuer: {$issuer}", 'ERROR');
    exit(1);
}

$oidcConfigUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';
$oidcConfig    = file_get_contents($oidcConfigUrl);

if ( ! $oidcConfig) {
    sleep(10);
    $oidcConfig = file_get_contents($oidcConfigUrl);
    if ( ! $oidcConfig) {
        logMessage("Failed to retrieve OIDC configuration from {$oidcConfigUrl}", 'ERROR');
        exec("/etc/rc.d/rc.tsidp restart");
    }
}

logMessage("TSIDP OIDC configuration is accessible at {$oidcConfigUrl}", 'INFO');
