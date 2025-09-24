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
