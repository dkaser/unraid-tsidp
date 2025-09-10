#!/usr/bin/env php
<?php

// configure-tsidp.php
// Configure tsidp as an OIDC provider in Unraid via GraphQL API

require_once __DIR__ . '/functions.php';

$keyName = 'tsidp';
$key     = createApiKey($keyName);

if ( ! $key) {
    logMessage("Failed to create API key with unraid-api\n", 'ERROR');
    safeExit(1, $keyName);
}

$tsidpPort = getTsidpPort();
if ( ! $tsidpPort) {
    logMessage("TSIDP_PORT not found in tsidp.cfg\n", 'ERROR');
    safeExit(1, 'tsidp');
}

// Get Tailscale status
$tailscaleJson = shell_exec('tailscale status -json 2>/dev/null');
if ( ! is_string($tailscaleJson) || $tailscaleJson === '') {
    logMessage("Failed to get tailscale status\n", 'ERROR');
    safeExit(1, $keyName);
}
$tailscale = json_decode($tailscaleJson, true);
if ( ! is_array($tailscale) || ! isset($tailscale['Self']) || ! is_array($tailscale['Self']) || ! isset($tailscale['Self']['DNSName']) || ! is_string($tailscale['Self']['DNSName'])) {
    logMessage("Self.DNSName not found in tailscale status\n", 'ERROR');
    safeExit(1, $keyName);
}

// Add the current tailscale DNS name and IP to /etc/hosts if not already present
// This ensures that Unraid can resolve the tsidp URL even if Tailscale DNS is not enabled.
$fqdn = rtrim((string)$tailscale['Self']['DNSName'], '.');
$ip   = null;
if (isset($tailscale['Self']['TailscaleIPs']) && is_array($tailscale['Self']['TailscaleIPs'])) {
    foreach ($tailscale['Self']['TailscaleIPs'] as $candidateIp) {
        if (is_string($candidateIp) && filter_var($candidateIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = $candidateIp;
            break;
        }
    }
}
if ( ! $ip) {
    logMessage("No IPv4 address found in Self.TailscaleIPs", 'ERROR');
    safeExit(1, $keyName);
}
updateHostsFile($fqdn, $ip);

// Configure tsidp as an OIDC provider in Unraid
$issuer = "https://{$fqdn}:{$tsidpPort}";

// Store the issuer in /var/run/tsidp-issuer for use by other scripts
file_put_contents('/var/run/tsidp-issuer', $issuer);

// Query unified settings
$unifiedQuery = 'query Unified { settings { unified { values } } }';
$resp         = graphql($unifiedQuery, [], $key);
if ( ! is_array($resp) || ! isset($resp['data']['settings']['unified']['values'])) {
    logMessage("Failed to get unified settings\n", 'ERROR');
    safeExit(1, $keyName);
}
$settings = $resp['data']['settings']['unified']['values'];
if ( ! is_array($settings) || ! isset($settings['sso']) || ! is_array($settings['sso'])) {
    logMessage("Invalid unified settings format\n", 'ERROR');
    safeExit(1, $keyName);
}

// Check for tsidp provider
if ( ! isset($settings['sso']['providers']) || ! is_array($settings['sso']['providers'])) {
    $settings['sso']['providers'] = [];
}
$exists = false;
foreach ($settings['sso']['providers'] as &$prov) {
    if (is_array($prov) && isset($prov['id']) && $prov['id'] === 'tsidp') {
        $exists = true;
        if ($prov['issuer'] === $issuer) {
            logMessage("tsidp provider already exists and configured correctly. No changes made.");
            safeExit(0, $keyName);
        }

        logMessage("Updating tsidp URL");
        $prov['issuer'] = $issuer;
        break;
    }
}

if ( ! $exists) {
    logMessage("Adding tsidp provider");
    $settings['sso']['providers'][] = createTsidpProvider($issuer);
}

// Update settings
$mutation   = 'mutation Mutation($input: JSON!) { updateSettings(input: $input) { restartRequired } }';
$vars       = [ 'input' => $settings ];
$updateResp = graphql($mutation, $vars, $key);
if ( ! $updateResp || ! isset($updateResp['data']['updateSettings'])) {
    logMessage("Failed to update settings\n", 'ERROR');
    safeExit(1, $keyName);
}

logMessage("tsidp provider configured successfully.");
deleteApiKey($keyName);
