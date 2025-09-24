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

// Add the current tailscale DNS name and IP to /etc/hosts if not already present
// This ensures that Unraid can resolve the tsidp URL even if Tailscale DNS is not enabled.
$tailscaleInfo = getTailscaleInfo();
if ( ! $tailscaleInfo) {
    logMessage("Failed to get Tailscale info\n", 'ERROR');
    safeExit(1, $keyName);
}

updateHostsFile($tailscaleInfo->fqdn, $tailscaleInfo->ip);

// Configure tsidp as an OIDC provider in Unraid
$issuer = "https://{$tailscaleInfo->fqdn}:{$tsidpPort}";

// Store the issuer in /var/run/tsidp-issuer for use by other scripts
file_put_contents('/var/run/tsidp-issuer', $issuer);

$clients = getClientsFile();
if ( ! isset($clients['unraidgui']) || ! isset($clients['unraidgui']['client_id']) || ! isset($clients['unraidgui']['client_secret']) || ! is_string($clients['unraidgui']['client_id'])) {
    logMessage("Invalid clients file format\n", 'ERROR');
    safeExit(1, $keyName);
}

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
logMessage("Current SSO settings retrieved.");
// Check for tsidp provider
if ( ! isset($settings['sso']['providers']) || ! is_array($settings['sso']['providers'])) {
    $settings['sso']['providers'] = [];
}
$exists = false;
foreach ($settings['sso']['providers'] as &$prov) {
    if (is_array($prov) && isset($prov['id']) && $prov['id'] === 'tsidp') {
        $exists   = true;
        $modified = false;

        if ($prov['issuer'] !== $issuer) {
            logMessage("Updating tsidp URL");
            $prov['issuer'] = $issuer;
            $modified       = true;
        }

        if ($prov['clientId'] !== $clients['unraidgui']['client_id']) {
            logMessage("Updating tsidp client_id");
            $prov['clientId'] = $clients['unraidgui']['client_id'];
            $modified         = true;
        }

        if ($prov['clientSecret'] !== $clients['unraidgui']['client_secret']) {
            logMessage("Updating tsidp client_secret");
            $prov['clientSecret'] = $clients['unraidgui']['client_secret'];
            $modified             = true;
        }

        if ( ! $modified) {
            logMessage("tsidp provider configured correctly, no changes needed.");
            safeExit(0, $keyName);
        }

        break;
    }
}

if ( ! $exists) {
    logMessage("Adding tsidp provider");
    $settings['sso']['providers'][] = createTsidpProvider($issuer, $clients['unraidgui']['client_id'], $clients['unraidgui']['client_secret']);
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
safeExit(0, $keyName);
