<#
.SYNOPSIS
    Admin-side signer for the xNinja license registry (ECDSA P-256 / ES256).

.DESCRIPTION
    The published registry must now be a SIGNED ENVELOPE. The client (XNinjaPlus)
    verifies the signature with an embedded PUBLIC key, so:
      - a hijacked raw.githubusercontent.com URL (hosts-file redirect) can no
        longer serve forged license data;
      - the AES layer (LicenseCrypto) keeps a confidentiality role only.

    Envelope published to the remote URL:
    {
      "alg":       "ES256",
      "crv":       "P-256",
      "payload":   "<base64url UTF-8 bytes of the original registry text>",
      "signature": "<base64url 64-byte r||s ECDSA-SHA256 over the payload bytes>"
    }

    Workflow:
      1. (once)    sign-licenses.ps1 -GenerateKeyPair
                   -> keep license-signing-key.json OFFLINE, never commit it
                   (the .gitignore in the repo root already excludes it)
      2. prepare your registry content as before: build it in the Admin Panel,
         save it locally (LoadLocalRegistry), export the AES blob through
         ExportEncrypted, or use plain JSON - any of these becomes the payload.
      3. sign-licenses.ps1 -Sign -InputFile <registry content> -KeyFile <keypair>
         -> writes <input>.signed.json for upload to
         https://raw.githubusercontent.com/<owner>/<repo>/main/licenses.json
      4. (optional) self-check: -Verify -InputFile <signed json> -KeyFile <keypair>

.EXAMPLE
    .\sign-licenses.ps1 -GenerateKeyPair
    .\sign-licenses.ps1 -GenerateKeyPair -OutFile D:\keys\license-signing-key.json

.EXAMPLE
    .\sign-licenses.ps1 -Sign -InputFile .\licenses-registry.txt -KeyFile D:\keys\license-signing-key.json

.EXAMPLE
    .\sign-licenses.ps1 -Verify -InputFile .\licenses-registry.txt.signed.json -KeyFile D:\keys\license-signing-key.json

.EXAMPLE
    .\sign-licenses.ps1 -ShowPublicKey -KeyFile D:\keys\license-signing-key.json
    (prints the C# constant snippet to paste into LicenseRegistrySignature.cs)
#>
[CmdletBinding(DefaultParameterSetName = 'Sign')]
param(
    [Parameter(ParameterSetName = 'Generate', Mandatory = $true)]
    [switch]$GenerateKeyPair,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$OutFile,

    [Parameter(ParameterSetName = 'Sign', Mandatory = $true)]
    [switch]$Sign,

    [Parameter(ParameterSetName = 'Verify', Mandatory = $true)]
    [switch]$Verify,

    [Parameter(ParameterSetName = 'ShowPublicKey', Mandatory = $true)]
    [switch]$ShowPublicKey,

    [string]$KeyFile,

    [Parameter(ParameterSetName = 'Sign', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Verify', Mandatory = $true)]
    [string]$InputFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# $PSScriptRoot is empty during parameter-default evaluation, resolve here.
if (-not $KeyFile)    { $KeyFile = Join-Path $PSScriptRoot 'license-signing-key.json' }
if (-not $OutFile)    { $OutFile = Join-Path $PSScriptRoot 'license-signing-key.json' }

function To-Hex([byte[]]$bytes) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

function From-Hex([string]$hex) {
    $out = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $out.Length; $i++) {
        $out[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return , $out
}

function Base64Url([byte[]]$bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Read-KeyPair([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Key file not found: $Path (generate one with -GenerateKeyPair)"
    }
    $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($json.crv -ne 'P-256') { throw "Unsupported curve: $($json.crv)" }
    return $json
}

function New-EcdsaFromPublicKey([object]$keyJson) {
    # ECParameters + public Q only - same construction the client embeds.
    $parameters = New-Object System.Security.Cryptography.ECParameters
    $parameters.Curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
    $point = New-Object System.Security.Cryptography.ECPoint
    $point.X = From-Hex $keyJson.x
    $point.Y = From-Hex $keyJson.y
    $parameters.Q = $point
    return [System.Security.Cryptography.ECDsa]::Create($parameters)
}

function New-EcdsaFromKeyPair([object]$keyJson) {
    $parameters = New-Object System.Security.Cryptography.ECParameters
    $parameters.Curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
    $point = New-Object System.Security.Cryptography.ECPoint
    $point.X = From-Hex $keyJson.x
    $point.Y = From-Hex $keyJson.y
    $parameters.Q = $point
    $parameters.D = From-Hex $keyJson.d
    return [System.Security.Cryptography.ECDsa]::Create($parameters)
}

# ----------------------------------------------------------------- keygen ---
if ($GenerateKeyPair) {
    if (Test-Path -LiteralPath $OutFile) {
        throw "Refusing to overwrite an existing keypair: $OutFile - move it first."
    }

    $genParams = New-Object System.Security.Cryptography.CngKeyCreationParameters
    $genParams.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
    $genParams.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing

    $cngKey = [System.Security.Cryptography.CngKey]::Create(
        [System.Security.Cryptography.CngAlgorithm]::ECDsaP256,
        ('xnp-sign-' + [Guid]::NewGuid().ToString('N')),
        $genParams)

    $ec = New-Object System.Security.Cryptography.ECDsaCng($cngKey)

    # This framework build leaves ECParameters.Q empty even for a full export,
    # so X/Y/D are parsed from the raw BCrypt ECC blob:
    #   [4B magic][4B cbKey][X (cbKey bytes)][Y (cbKey bytes)][D (cbKey bytes)]
    $privBlob = $cngKey.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
    $cbKey = [BitConverter]::ToInt32($privBlob, 4)
    if ($cbKey -ne 32) { throw "Unexpected P-256 blob size: $cbKey" }
    $x = [byte[]]$privBlob[8..39]
    $y = [byte[]]$privBlob[40..71]
    $d = [byte[]]$privBlob[72..103]

    $keyJson = [ordered]@{
        alg     = 'ES256-P256'
        crv     = 'P-256'
        d       = (To-Hex $d)
        x       = (To-Hex $x)
        y       = (To-Hex $y)
        created = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    $out = $keyJson | ConvertTo-Json -Depth 3
    [IO.File]::WriteAllText($OutFile, $out)

    Write-Host ''
    Write-Host "Key pair written to: $OutFile" -ForegroundColor Green
    Write-Host ''
    Write-Host '  KEEP THIS FILE OFFLINE AND SECRET. Never commit it, never ship it.' -ForegroundColor Yellow
    Write-Host '  Anyone holding it can publish registries your clients trust.'      -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Public key (for LicenseRegistrySignature.cs):' -ForegroundColor Cyan
    Write-Host ('  x = "{0}"' -f $keyJson.x)
    Write-Host ('  y = "{0}"' -f $keyJson.y)
    return
}

# ------------------------------------------------------------------- sign ---
if ($Sign) {
    $key = Read-KeyPair $KeyFile
    $content = [IO.File]::ReadAllText($InputFile)
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes($content)

    $ecdsa = New-EcdsaFromKeyPair $key

    # .NET's SignData returns r||s (64 bytes for P-256) - the long form the
    # client expects. On Windows PowerShell 5.1 the NCrypt provider may return
    # an ASN.1 signature; normalize to the fixed 64-byte form either way.
    $sigRaw = $ecdsa.SignData($payloadBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($sigRaw.Length -ne 64) {
        # DER (SEQUENCE { INTEGER r, INTEGER s }) -> fixed 64-byte r||s.
        $r = New-Object byte[] 32
        $s = New-Object byte[] 32
        $i = 2                      # skip 0x30 len
        if ($sigRaw[0] -ne 0x30) { throw 'Unexpected signature format (expected DER SEQUENCE)' }
        if ($sigRaw[$i] -ne 0x02) { throw 'Unexpected signature format (expected INTEGER r)' }
        $i += 1
        $rLen = [int]$sigRaw[$i]; $i += 1
        # strip a leading zero padding byte, keep last 32 bytes at most
        $rBody = $sigRaw[$i..($i + $rLen - 1)]
        while ($rBody.Length -gt 0 -and $rBody[0] -eq 0 -and $rBody.Length -gt 32) { $rBody = $rBody[1..($rBody.Length - 1)] }
        $rOff = 32 - [Math]::Min(32, $rBody.Length)
        for ($k = 0; $k -lt [Math]::Min($rBody.Length, 32); $k++) { $r[$rOff + $k] = $rBody[[Math]::Max(0, $rBody.Length - 32) + $k] }

        $i += $rLen
        if ($sigRaw[$i] -ne 0x02) { throw 'Unexpected signature format (expected INTEGER s)' }
        $i += 1
        $sLen = [int]$sigRaw[$i]; $i += 1
        $sBody = $sigRaw[$i..($i + $sLen - 1)]
        while ($sBody.Length -gt 0 -and $sBody[0] -eq 0 -and $sBody.Length -gt 32) { $sBody = $sBody[1..($sBody.Length - 1)] }
        $sOff = 32 - [Math]::Min(32, $sBody.Length)
        for ($k = 0; $k -lt [Math]::Min($sBody.Length, 32); $k++) { $s[$sOff + $k] = $sBody[[Math]::Max(0, $sBody.Length - 32) + $k] }

        $sig = $r + $s
    } else {
        $sig = $sigRaw
    }

    $envelope = [ordered]@{
        alg       = 'ES256'
        crv       = 'P-256'
        payload   = (Base64Url $payloadBytes)
        signature = (Base64Url ([byte[]]$sig))
    }

    $dest = "$InputFile.signed.json"
    [IO.File]::WriteAllText($dest, ($envelope | ConvertTo-Json -Depth 3))

    Write-Host "Signed envelope written to: $dest" -ForegroundColor Green
    Write-Host "Upload this file as licenses.json. The client refuses un-signed content." -ForegroundColor Yellow
    return
}

# ------------------------------------------------------------------ verify ---
if ($Verify) {
    $key = Read-KeyPair $KeyFile
    $envelopeJson = [IO.File]::ReadAllText($InputFile)
    $env2 = $envelopeJson | ConvertFrom-Json

    $payloadBytes = [Convert]::FromBase64String(
        $env2.payload.Replace('-', '+').Replace('_', '/') + ('=' * ((4 - ($env2.payload.Length % 4)) % 4)))
    $sigBytes = [Convert]::FromBase64String(
        $env2.signature.Replace('-', '+').Replace('_', '/') + ('=' * ((4 - ($env2.signature.Length % 4)) % 4)))

    $ecdsa = New-EcdsaFromPublicKey $key
    $ok = $ecdsa.VerifyData([byte[]]$payloadBytes, [byte[]]$sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)

    if ($ok) {
        Write-Host 'SIGNATURE VALID' -ForegroundColor Green
        $payloadText = [Text.Encoding]::UTF8.GetString($payloadBytes)
        if ($payloadText.TrimStart().StartsWith('{')) {
            Write-Host 'payload preview:' -ForegroundColor Cyan
            Write-Host ($payloadText.Substring(0, [Math]::Min(400, $payloadText.Length)))
        } else {
            Write-Host ("payload = AES blob ({0} chars (encrypted), verification of the envelope is sufficient)" -f $payloadText.Length) -ForegroundColor Cyan
        }
    } else {
        Write-Host 'SIGNATURE INVALID - do not upload this file' -ForegroundColor Red
        exit 1
    }
    return
}

# ------------------------------------------------------------ show pubkey ---
if ($ShowPublicKey) {
    $key = Read-KeyPair $KeyFile
    Write-Host 'Paste into LicenceRegistrySignature.cs (replace both constants):' -ForegroundColor Cyan
    Write-Host ''
    Write-Host ('        private static readonly byte[] PubX = Convert.FromHexString(')
    Write-Host ('            "' + $key.x + '");')
    Write-Host ('        private static readonly byte[] PubY = Convert.FromHexString(')
    Write-Host ('            "' + $key.y + '");')
    Write-Host ''
    Write-Host 'Then rebuild and publish so the new public key ships inside the client.' -ForegroundColor Yellow
    return
}

throw 'unreachable'
