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

class TailscaleInfo
{
    public string $fqdn;
    public string $ip;

    public function __construct(string $fqdn, string $ip)
    {
        $this->fqdn = $fqdn;
        $this->ip   = $ip;
    }
}

function logMessage(string $message, string $level = 'INFO', array $context = []): void
{
    $timestamp  = date('Y-m-d H:i:s');
    $contextStr = $context ? json_encode($context) : '';
    echo "[{$timestamp}] {$level}: {$message} {$contextStr}\n";
}

function getClientsFile(): array
{
    $clientsFile = '/boot/config/plugins/tsidp/oidc-funnel-clients.json';
    if (file_exists($clientsFile)) {
        $clientsJson = file_get_contents($clientsFile);
        if ($clientsJson === false) {
            logMessage("Failed to read existing clients file, initializing empty clients list\n", 'WARNING');
            $clients = [];
        } else {
            $clients = (array)json_decode($clientsJson, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                logMessage("Existing clients file is invalid JSON, initializing empty clients list\n", 'WARNING');
                $clients = [];
            }
        }
    } else {
        $clients = [];
    }
    return $clients;
}

function createApiKey(string $name): string|null
{
    $cmd        = escapeshellcmd("unraid-api apikey --create --name {$name} -r ADMIN -d temporary --json --overwrite 2>/dev/null");
    $apikeyJson = shell_exec($cmd);
    if (is_string($apikeyJson) && $apikeyJson !== '') {
        $apikey = json_decode($apikeyJson, true);
        if (is_array($apikey) && isset($apikey['key']) && is_string($apikey['key'])) {
            return $apikey['key'];
        }
    }
    return null;
}

function getTailscaleInfo(): TailscaleInfo|null
{
    // Get Tailscale status
    $tailscaleJson = shell_exec('tailscale status -json 2>/dev/null');
    if ( ! is_string($tailscaleJson) || $tailscaleJson === '') {
        logMessage("Failed to get tailscale status\n", 'ERROR');
        return null;
    }
    $tailscale = json_decode($tailscaleJson, true);
    if ( ! is_array($tailscale) || ! isset($tailscale['Self']) || ! is_array($tailscale['Self']) || ! isset($tailscale['Self']['DNSName']) || ! is_string($tailscale['Self']['DNSName'])) {
        logMessage("Self.DNSName not found in tailscale status\n", 'ERROR');
        return null;
    }
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
        return null;
    }
    return new TailscaleInfo($fqdn, $ip);
}

function getConfigValue(string $key): string|null
{
    $cfgFile = '/boot/config/plugins/tsidp/tsidp.cfg';
    if (file_exists($cfgFile)) {
        $ini = parse_ini_file($cfgFile);
        if (isset($ini[$key]) && is_string($ini[$key])) {
            return $ini[$key];
        }
    }
    return null;
}

function getAllowedHosts(): array
{
    $allowedHosts = getConfigValue('ALLOWED_HOSTS');
    if ($allowedHosts === null || trim($allowedHosts) === '') {
        return [];
    }
    return array_filter(array_map('trim', explode(' ', $allowedHosts)));
}

function getIpAddresses(): array
{
    $interfaces = net_get_interfaces() ?: [];

    // For each interface, get the IPv4 addresses
    $ipv4_addresses    = [];
    $excluded_prefixes = ['lo', 'br-', 'veth', 'docker', 'virbr'];

    foreach ($interfaces as $interface_name => $interface_data) {
        // Check if the interface name starts with any of the excluded prefixes
        $exclude = false;
        foreach ($excluded_prefixes as $prefix) {
            if (str_starts_with($interface_name, $prefix)) {
                $exclude = true;
                break;
            }
        }
        if ($exclude) {
            continue;
        }

        if (isset($interface_data['unicast'])) {
            foreach ($interface_data['unicast'] as $unicast) {
                if (isset($unicast['family']) && $unicast['family'] == 2 && isset($unicast['address'])) {
                    $ipv4_addresses[] = $unicast['address'];
                }
            }
        }
    }
    return $ipv4_addresses;
}

function getTsidpPort(): int|null
{
    // Read TSIDP_PORT from tsidp.cfg
    $tsidpPort = getConfigValue('TSIDP_PORT');
    if ($tsidpPort === null || ! is_numeric($tsidpPort) || (int)$tsidpPort < 1 || (int)$tsidpPort > 65535) {
        return null;
    }
    return (int)$tsidpPort;
}

function deleteApiKey(string $name): void
{
    $cmd = escapeshellcmd("unraid-api apikey --delete --name {$name} --json 2>/dev/null");
    shell_exec($cmd);
}

/**
 * @return never
 */
function safeExit(int $code, string $keyName): void
{
    deleteApiKey($keyName);
    exit($code);
}

function graphql(string $query, array $variables = [], string $key = ""): array|null
{
    $sock    = '/var/run/unraid-api.sock';
    $headers = [
        'Host: localhost',
        'Content-Type: application/json',
    ];
    if ($key) {
        $headers[] = "X-Api-Key: {$key}";
    }
    $body = [ 'query' => $query ];
    if ($variables) {
        $body['variables'] = $variables;
    }
    $jsonBody = json_encode($body);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_UNIX_SOCKET_PATH, $sock);
    curl_setopt($ch, CURLOPT_URL, 'http://localhost/graphql');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonBody ?: "");
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FAILONERROR, false);
    $result = curl_exec($ch);
    if ($result === false) {
        curl_close($ch);
        return null;
    }
    curl_close($ch);
    return is_string($result) ? (array)json_decode($result, true) : null;
}

function createTsidpProvider(string $issuer, string $clientId, string $clientSecret): array
{
    return [
        'id'                    => 'tsidp',
        'name'                  => 'Tailscale',
        'clientId'              => $clientId,
        'clientSecret'          => $clientSecret,
        'issuer'                => $issuer,
        'scopes'                => ['openid', 'profile', 'email'],
        'authorizationRuleMode' => 'or',
        'authorizationRules'    => [],
        'buttonText'            => '',
        'buttonVariant'         => 'outline',
        'buttonStyle'           => 'background-color: #ffffff; color: #000000;',
        'buttonIcon'            => getTailscaleIcon(),
        'isProtected'           => false,
        'authorizationMode'     => 'simple',
        'simpleAuthorization'   => [
            'allowedDomains' => [],
            'allowedEmails'  => [],
            'allowedUserIds' => []
        ]
    ];
}

function getTailscaleIcon(): string
{
    // Move the base64 icon to a separate function for better readability
    return 'data:image/png;base64,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';
}

function updateHostsFile(string $fqdn, string $ip): void
{
    $hostsFile = '/etc/hosts';
    $hosts     = file($hostsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

    $entry = "{$ip} {$fqdn}";
    $found = false;
    foreach ($hosts as $i => $line) {
        // Split line into tokens
        $tokens = preg_split('/\s+/', trim($line)) ?: [];
        if (count($tokens) < 2) {
            continue;
        }

        $lineIp    = $tokens[0];
        $hostnames = array_slice($tokens, 1);

        if ($lineIp === $ip) {
            if (in_array($fqdn, $hostnames, true)) {
                $found = true;
                break;
            } else {
                // Add fqdn to this line if not present
                $hostnames[] = $fqdn;
                $hosts[$i]   = $lineIp . ' ' . implode(' ', array_unique($hostnames));
                file_put_contents($hostsFile, implode(PHP_EOL, $hosts) . PHP_EOL, LOCK_EX);
                logMessage("Updated {$hostsFile} to include {$fqdn} for {$ip}");
                $found = true;
                break;
            }
        }
    }
    if ( ! $found) {
        file_put_contents($hostsFile, $entry . PHP_EOL, FILE_APPEND | LOCK_EX);
        logMessage("Added {$entry} to {$hostsFile}");
    } else {
        logMessage("{$entry} already exists in {$hostsFile}");
    }
}
