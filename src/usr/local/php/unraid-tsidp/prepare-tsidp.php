#!/usr/bin/env php
<?php

// prepare-tsidp.php
// Prepare the /boot/config/plugins/tsidp/oidc-funnel-clients.json file for use with tsidp

require_once __DIR__ . '/functions.php';

$clients = getClientsFile();

$tailscaleInfo = getTailscaleInfo();
if ( ! $tailscaleInfo) {
    logMessage("Failed to get Tailscale info\n", 'ERROR');
    exit(1);
}

$identFile   = '/boot/config/ident.cfg';
$webguiPort  = 80;
$webguiProto = 'http';
if (file_exists($identFile)) {
    $identCfg = parse_ini_file($identFile);
    if ($identCfg !== false) {
        if (isset($identCfg['USE_SSL']) && strtolower($identCfg['USE_SSL']) === 'yes' && isset($identCfg['PORTSSL']) && is_numeric($identCfg['PORTSSL'])) {
            $webguiPort  = (int)$identCfg['PORTSSL'];
            $webguiProto = 'https';
        } elseif (isset($identCfg['PORT']) && is_numeric($identCfg['PORT'])) {
            $webguiPort = (int)$identCfg['PORT'];
        }
    } else {
        logMessage("Failed to parse ident.cfg, defaulting to HTTP port 80\n", 'WARNING');
    }
} else {
    logMessage("ident.cfg not found, defaulting to HTTP port 80\n", 'WARNING');
}

if ($webguiPort == 80 && $webguiProto == 'http') {
    $webguiPort = "";
} elseif ($webguiPort == 443 && $webguiProto == 'https') {
    $webguiPort = "";
} else {
    $webguiPort = ":{$webguiPort}";
}

// Create a random client secret
$clientSecretLength = 32;
if (isset($clients['unraidgui']['client_secret']) && is_string($clients['unraidgui']['client_secret']) && strlen($clients['unraidgui']['client_secret']) >= $clientSecretLength) {
    // Reuse existing client secret if it meets the length requirement
    $clientSecret = $clients['unraidgui']['client_secret'];
} else {
    logMessage("Generating new unraidgui client_secret\n");
    $clientSecret = substr(str_shuffle('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, $clientSecretLength);
}

// Update the unraidgui client entry
$clients['unraidgui'] = [
    "client_id"     => "unraidgui",
    "client_secret" => $clientSecret,
    "redirect_uris" => [
        "{$webguiProto}://{$tailscaleInfo->fqdn}{$webguiPort}/graphql/api/auth/oidc/callback"
    ],
    "created_at"   => "0001-01-01T00:00:00Z",
    "redirect_uri" => "{$webguiProto}://{$tailscaleInfo->fqdn}{$webguiPort}/graphql/api/auth/oidc/callback"
];

$clientsJson = json_encode($clients, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if ($clientsJson === false) {
    logMessage("Failed to encode clients to JSON\n", 'ERROR');
    exit(1);
}

$clientsFile = '/boot/config/plugins/tsidp/oidc-funnel-clients.json';
if (file_put_contents($clientsFile, $clientsJson) === false) {
    logMessage("Failed to write clients file\n", 'ERROR');
    exit(1);
}
logMessage("Successfully updated clients file at {$clientsFile}\n");
exit(0);
