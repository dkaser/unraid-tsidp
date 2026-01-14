#!/usr/bin/env php
<?php

/*
    Copyright (C) 2025  Derek Kaser

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// prepare-tsidp.php
// Prepare the /boot/config/plugins/tsidp/oidc-funnel-clients.json file for use with tsidp

require_once __DIR__ . '/functions.php';

$clients = getClientsFile();

$tailscaleInfo = getTailscaleInfo();
if ( ! $tailscaleInfo) {
    logMessage("Failed to get Tailscale info", 'ERROR');
    exit(1);
}

$identFile = '/boot/config/ident.cfg';
$httpPort  = 80;
$httpsPort = 443;

if (file_exists($identFile)) {
    $identCfg = parse_ini_file($identFile);
    if ($identCfg !== false) {
        if (isset($identCfg['PORTSSL']) && is_numeric($identCfg['PORTSSL'])) {
            $httpsPort = (int)$identCfg['PORTSSL'];
        }
        if (isset($identCfg['PORT']) && is_numeric($identCfg['PORT'])) {
            $httpPort = (int)$identCfg['PORT'];
        }
    } else {
        logMessage("Failed to parse ident.cfg, using default ports", 'WARNING');
    }
} else {
    logMessage("ident.cfg not found, using default ports", 'WARNING');
}

logMessage("Using HTTP port: {$httpPort}, HTTPS port: {$httpsPort}");

$allowedHosts   = getAllowedHosts();
$allowedHosts   = array_merge($allowedHosts, getIpAddresses());
$allowedHosts[] = $tailscaleInfo->fqdn;
$redirect_uris  = [];

foreach ($allowedHosts as $host) {
    $host = trim($host);
    if ($host === '') {
        continue;
    }

    if (filter_var($host, FILTER_VALIDATE_URL)) {
        if ( ! in_array(parse_url($host, PHP_URL_SCHEME), ['http', 'https'], true)) {
            logMessage("Skipping URL with unsupported scheme: {$host}", 'WARNING');
            continue;
        }
        logMessage("Processing allowed host with scheme: {$host}");
        $redirect_uris[] = rtrim($host, '/') . '/graphql/api/auth/oidc/callback';
        continue;
    }

    // Validate the hostname
    if ( ! (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || filter_var($host, FILTER_VALIDATE_IP))) {
        logMessage("Skipping invalid hostname: {$host}", 'WARNING');
        continue;
    }

    logMessage("Processing allowed host: {$host}");

    // HTTP redirect URI
    $redirect_uris[] = "http://{$host}:{$httpPort}/graphql/api/auth/oidc/callback";
    if ($httpPort === 80) {
        $redirect_uris[] = "http://{$host}/graphql/api/auth/oidc/callback";
    }
    // HTTPS redirect URI
    $redirect_uris[] = "https://{$host}:{$httpsPort}/graphql/api/auth/oidc/callback";
    if ($httpsPort === 443) {
        $redirect_uris[] = "https://{$host}/graphql/api/auth/oidc/callback";
    }
}

$redirect_uris = array_unique($redirect_uris);

// Create a random client secret
$clientSecretLength = 32;
if (isset($clients['unraidgui']['client_secret']) && is_string($clients['unraidgui']['client_secret']) && strlen($clients['unraidgui']['client_secret']) >= $clientSecretLength) {
    // Reuse existing client secret if it meets the length requirement
    $clientSecret = $clients['unraidgui']['client_secret'];
} else {
    logMessage("Generating new unraidgui client_secret");
    $clientSecret = substr(str_shuffle('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, $clientSecretLength);
}

// Update the unraidgui client entry
$clients['unraidgui'] = [
    "client_id"     => "unraidgui",
    "client_secret" => $clientSecret,
    "redirect_uris" => array_values($redirect_uris),
    "created_at"    => "0001-01-01T00:00:00Z",
    "redirect_uri"  => "https://{$tailscaleInfo->fqdn}:{$httpsPort}/graphql/api/auth/oidc/callback"
];

$clientsJson = json_encode($clients, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if ($clientsJson === false) {
    logMessage("Failed to encode clients to JSON", 'ERROR');
    exit(1);
}

$clientsFile = '/boot/config/plugins/tsidp/oidc-funnel-clients.json';
if (file_put_contents($clientsFile, $clientsJson) === false) {
    logMessage("Failed to write clients file", 'ERROR');
    exit(1);
}
logMessage("Successfully updated clients file at {$clientsFile}");
exit(0);
