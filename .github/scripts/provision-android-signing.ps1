[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository,
    [Parameter(Mandatory = $true)]
    [string]$GitHubCli
)

$ErrorActionPreference = 'Stop'
if (!$env:GH_TOKEN) { throw 'Provide GitHub authentication in the process environment, not a command-line argument.' }
if (!(Test-Path -LiteralPath $GitHubCli -PathType Leaf)) { throw 'Verified GitHub CLI executable was not found.' }

function Send-GitHubValue {
    param([string]$Kind, [string]$Name, [string]$Value)
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $GitHubCli
    $start.Arguments = "$Kind set $Name --repo $Repository"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (!$process.Start()) { throw 'GitHub CLI could not start.' }
        $process.StandardInput.Write($Value)
        $process.StandardInput.Close()
        $output = $process.StandardOutput.ReadToEnd()
        $errorOutput = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "GitHub $Kind upload failed for $Name (exit $($process.ExitCode)); secret content was not logged."
        }
    } finally {
        $process.Dispose()
    }
}

$directory = Join-Path $env:LOCALAPPDATA 'GuvenliBaglantiSigning'
$keyFile = Join-Path $directory 'android-release.p12'
$stateFile = Join-Path $directory 'android-release.secrets.clixml'
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $directory /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict signing-key directory permissions.' }

if ((Test-Path -LiteralPath $keyFile) -ne (Test-Path -LiteralPath $stateFile)) {
    throw 'Incomplete signing backup; refusing to replace or rotate an existing release key.'
}

$password = $null
$certificate = $null
$rsa = $null
try {
    if (!(Test-Path -LiteralPath $keyFile)) {
        $random = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($random) } finally { $rng.Dispose() }
        $password = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        [Array]::Clear($random, 0, $random.Length)
        $rsa = [Security.Cryptography.RSACng]::new(3072)
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=GuvenliBaglanti Android Release, O=Personal Remote Access, C=TR',
            $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddYears(20))
        $certificate.FriendlyName = 'guvenlibaglanti'
        [IO.File]::WriteAllBytes($keyFile, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password))
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        [pscustomobject]@{ Password = $securePassword; Alias = 'guvenlibaglanti' } | Export-Clixml -LiteralPath $stateFile
    } else {
        $state = Import-Clixml -LiteralPath $stateFile
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($state.Password)
        try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($keyFile, $password, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    }
    if (!$certificate.HasPrivateKey -or $certificate.FriendlyName -ne 'guvenlibaglanti') {
        throw 'Signing backup identity did not validate; refusing to publish signing material.'
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { $fingerprint = ([BitConverter]::ToString($sha256.ComputeHash($certificate.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose() }
    Send-GitHubValue 'secret' 'ANDROID_SIGNING_KEY' ([Convert]::ToBase64String([IO.File]::ReadAllBytes($keyFile)))
    Send-GitHubValue 'secret' 'ANDROID_KEY_STORE_PASSWORD' $password
    Send-GitHubValue 'secret' 'ANDROID_KEY_PASSWORD' $password
    Send-GitHubValue 'secret' 'ANDROID_ALIAS' 'guvenlibaglanti'
    Send-GitHubValue 'variable' 'ANDROID_SIGNING_CERT_SHA256' $fingerprint
    [pscustomobject]@{
        Repository = $Repository
        SigningCertificateSHA256 = $fingerprint
        BackupDirectory = $directory
        PasswordBackup = 'Windows DPAPI; tied to this Windows user and machine. Preserve a recoverable key/password backup before migration.'
        SecretsUploaded = $true
    } | ConvertTo-Json -Compress
} finally {
    if ($certificate) { $certificate.Dispose() }
    if ($rsa) { $rsa.Dispose() }
    $password = $null
}
