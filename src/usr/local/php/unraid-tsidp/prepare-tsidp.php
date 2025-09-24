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
    logMessage("Failed to get Tailscale info\n", 'ERROR');
    exit(1);
}

$identFile   = '/boot/config/ident.cfg';
$webguiPort  = 80;
$webguiProto = 'http';

// "{$webguiProto}://{$tailscaleInfo->fqdn}{$webguiPort}/graphql/api/auth/oidc/callback"
$redirect_uris = [];

if (file_exists($identFile)) {
    $identCfg = parse_ini_file($identFile);
    if ($identCfg !== false) {
        if (isset($identCfg['PORTSSL']) && is_numeric($identCfg['PORTSSL'])) {
            $webguiPort      = (int)$identCfg['PORTSSL'];
            $redirect_uris[] = "https://{$tailscaleInfo->fqdn}:{$webguiPort}/graphql/api/auth/oidc/callback";
            if ($webguiPort == 443) {
                $redirect_uris[] = "https://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
            }
        } else {
            $redirect_uris[] = "https://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
        }
        if (isset($identCfg['PORT']) && is_numeric($identCfg['PORT'])) {
            $webguiPort      = (int)$identCfg['PORT'];
            $redirect_uris[] = "http://{$tailscaleInfo->fqdn}:{$webguiPort}/graphql/api/auth/oidc/callback";
            if ($webguiPort == 80) {
                $redirect_uris[] = "http://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
            }
        } else {
            $redirect_uris[] = "http://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
        }
    } else {
        logMessage("Failed to parse ident.cfg, defaulting to default HTTP(s) ports\n", 'WARNING');
        $redirect_uris[] = "http://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
        $redirect_uris[] = "https://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
    }
} else {
    logMessage("ident.cfg not found, defaulting to default HTTP(s) ports\n", 'WARNING');
    $redirect_uris[] = "http://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
    $redirect_uris[] = "https://{$tailscaleInfo->fqdn}/graphql/api/auth/oidc/callback";
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
    "redirect_uris" => $redirect_uris,
    "created_at"    => "0001-01-01T00:00:00Z",
    "redirect_uri"  => "{$webguiProto}://{$tailscaleInfo->fqdn}:{$webguiPort}/graphql/api/auth/oidc/callback"
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
