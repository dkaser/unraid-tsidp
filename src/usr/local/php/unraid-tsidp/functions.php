<?php

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
