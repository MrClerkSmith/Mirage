# Mirage client installer for Windows.
#
# Run in an elevated PowerShell (Wintun needs admin rights):
#   powershell -c "irm https://raw.githubusercontent.com/MrClerkSmith/Mirage/main/deploy/install-client.ps1 | iex"
#
# At the end it asks for the client config: either a path to a client.json,
# or the one-line base64 config printed by the server installer.
#
# To install without a terminal, pass the config on the command line:
#   .\install-client.ps1 -ConfigB64 "eyJtb2RlIj...."
#   .\install-client.ps1 -ConfigFile C:\Users\me\Downloads\home.json

param(
	[string]$ConfigFile = "",
	[string]$ConfigB64 = "",
	[string]$Dir = "C:\mirage",
	[switch]$Foreground,
	[string]$Branch = "main"
)

$ErrorActionPreference = "Stop"
$REPO_URL = "https://github.com/MrClerkSmith/Mirage.git"
$SERVICE = "MirageClient"

function Write-Step($msg) { Write-Host "== $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Host "== $msg" -ForegroundColor Red; exit 1 }

$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
	Die "run this script as administrator (Wintun needs it)"
}

# ---------- config ----------

if ($ConfigFile -ne "" -and (Test-Path $ConfigFile)) {
	$json = Get-Content -Raw $ConfigFile
} elseif ($ConfigB64 -ne "") {
	$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigB64))
} else {
	Write-Step "client config"
	Write-Host "Paste the client config from the server:"
	Write-Host "  - a path to client.json, or"
	Write-Host "  - the one-line base64 config the server installer printed, then an empty line"
	$line = Read-Host "config"
	if ((Test-Path $line -ErrorAction SilentlyContinue)) {
		$json = Get-Content -Raw $line
	} else {
		try { $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line)) }
		catch { Die "that is neither a file nor valid base64" }
	}
}
if (-not ($json -match '"server_addr"')) { Die "the config does not look like a Mirage client config" }

# ---------- go ----------

$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
	Write-Step "installing Go"
	$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
	$url = "https://go.dev/dl/go1.23.4.windows-$arch.msi"
	$msi = "$env:TEMP\go.msi"
	Invoke-WebRequest -Uri $url -OutFile $msi
	Start-Process msiexec.exe -ArgumentList "/i", $msi, "/quiet" -Wait
	Remove-Item $msi
	$env:Path += ";C:\Program Files\Go\bin"
	$go = Get-Command go -ErrorAction SilentlyContinue
	if (-not $go) { Die "Go did not install; get it from https://go.dev/dl/ and rerun" }
} else {
	Write-Step "go already installed"
}

# ---------- source and build ----------

if (Test-Path "$Dir\.git") {
	Write-Step "updating $Dir"
	Push-Location $Dir
	git pull --ff-only
	Pop-Location
} else {
	Write-Step "cloning into $Dir"
	git clone --depth 1 -b $Branch $REPO_URL $Dir
}

Write-Step "building"
	Push-Location $Dir
	go build -buildvcs=false -o mirage.exe ./cmd/mirage
	Pop-Location
if (-not (Test-Path "$Dir\mirage.exe")) { Die "build failed" }

# ---------- config file ----------

$cfg = "$Dir\client.json"
[System.IO.File]::WriteAllText($cfg, $json)

# ---------- run ----------

if ($Foreground) {
	Write-Step "running in the foreground (ctrl-c to stop)"
	& "$Dir\mirage.exe" client -c $cfg
	return
}

$svc = Get-Service -Name $SERVICE -ErrorAction SilentlyContinue
if ($svc) {
	Write-Step "restarting the $SERVICE service"
	Stop-Service $SERVICE -ErrorAction SilentlyContinue
	& sc.exe delete $SERVICE | Out-Null
}
Write-Step "installing the $SERVICE service"
& sc.exe create $SERVICE binPath= "$Dir\mirage.exe client -c $cfg" start= auto | Out-Null
& sc.exe description $SERVICE "Mirage DPI-resistant VPN client" | Out-Null
Start-Service $SERVICE

Write-Host ""
Write-Step "done"
Write-Host "service:  $SERVICE (starts on boot)"
Write-Host "config:   $cfg"
Write-Host "trouble:  to see the logs run this script again with -Foreground"
Write-Host "stop:     Stop-Service $SERVICE   (remove: sc.exe delete $SERVICE)"
