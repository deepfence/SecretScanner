<#
run_scanner.ps1 - helper to run Deepfence SecretScanner from PowerShell or WSL

Usage examples:
  # Preferred: run inside WSL (bash/zsh) or use -UseWSL switch which will invoke docker under WSL
  .\run_scanner.ps1 -License "YOUR_LICENSE_HERE" -Product ThreatMapper

  # Run with explicit image and output file
  .\run_scanner.ps1 -License "YOUR_LICENSE_HERE" -Product ThreatMapper -ImageTag 2.5.7 -OutputFile node.json

This script will attempt to use WSL if present (recommended) because that ensures /var/run/docker.sock is available.
If WSL is not available, it'll run the docker command in PowerShell.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$License,

    [Parameter(Mandatory=$false)]
    [string]$Product = "ThreatMapper",

    [Parameter(Mandatory=$false)]
    [string]$Image = "quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.7",

    [Parameter(Mandatory=$false)]
    [string]$ImageName = "node:8.11",

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "node.json",

    [switch]$UseWSL
)

function Test-DockerClient {
    try {
        docker --version > $null 2>&1
        return $true
    } catch {
        return $false
    }
}

Write-Host "Starting SecretScanner runner..." -ForegroundColor Cyan

if (-not $License -or $License -eq "YOUR_LICENSE_HERE") {
    Write-Error "Please pass a valid license value with -License 'YOUR_LICENSE_HERE' (replace placeholder)."
    exit 2
}

# Determine whether to run inside WSL
$haveWsl = (Get-Command wsl -ErrorAction SilentlyContinue) -ne $null
if ($UseWSL) {
    if (-not $haveWsl) {
        Write-Warning "-UseWSL requested but WSL not found. Falling back to Windows PowerShell docker client.";
        $UseWSL = $false
    }
} else {
    # default: prefer WSL if available
    if ($haveWsl) { $UseWSL = $true }
}

if ($UseWSL) {
    Write-Host "Running scanner under WSL (recommended). Output will be written to Linux-format file inside WSL, then copied to Windows if needed." -ForegroundColor Green

    # Ensure docker is available in WSL
    $wslDockerCheck = wsl docker --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Docker not available inside WSL. Ensure Docker Desktop WSL integration is enabled or run the script from Windows PowerShell."
    }

    # Build the WSL command - quote arguments carefully
    $wslCmd = @(
        'docker','run','-i','--rm','--name=deepfence-secretscanner',
        '-e',"DEEPFENCE_PRODUCT=$Product",
        '-e',"DEEPFENCE_LICENSE=$License",
        '-v','/var/run/docker.sock:/var/run/docker.sock',
        "$Image",
        "--image-name","$ImageName","--output","json"
    ) -join ' '

    # Run under wsl and redirect output to a file inside WSL /tmp then copy to Windows path
    $tmpWslPath = "/tmp/$(Get-Random)-scanner-output.json"
    $fullCmd = "bash -lc '$wslCmd > $tmpWslPath'"

    Write-Host "Invoking: wsl $fullCmd" -ForegroundColor Gray
    wsl $fullCmd

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Scanner container failed inside WSL (exit code $LASTEXITCODE). Check Docker logs or run interactively for more info."
        exit $LASTEXITCODE
    }

    # Copy file from WSL to Windows working directory
    $winDst = Join-Path -Path (Get-Location) -ChildPath $OutputFile
    Write-Host "Copying $tmpWslPath -> $winDst" -ForegroundColor Gray
    wsl cp $tmpWslPath - | Out-File -FilePath $winDst -Encoding utf8

    # Remove WSL temp file
    wsl rm -f $tmpWslPath

    Write-Host "Finished — output saved to $winDst" -ForegroundColor Green
    exit 0
}

# Fallback to Windows PowerShell docker client
Write-Host "Running scanner directly from PowerShell (PowerShell will invoke docker)." -ForegroundColor Green

if (-not (Test-DockerClient)) {
    Write-Error "Docker CLI not found in your PATH. Start Docker Desktop and try again or use -UseWSL if you have WSL installed."
    exit 3
}

$psCmd = @(
    'docker','run','-i','--rm','--name=deepfence-secretscanner',
    '-e',"DEEPFENCE_PRODUCT=$Product",
    '-e',"DEEPFENCE_LICENSE=$License",
    '-v','/var/run/docker.sock:/var/run/docker.sock',
    "$Image",
    '--image-name',"$ImageName",'--output','json'
) -join ' '

Write-Host "Invoking: $psCmd" -ForegroundColor Gray

# Run the command directly and capture output
try {
    $out = & docker run -i --rm --name=deepfence-secretscanner -e "DEEPFENCE_PRODUCT=$Product" -e "DEEPFENCE_LICENSE=$License" -v /var/run/docker.sock:/var/run/docker.sock $Image --image-name $ImageName --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "docker run failed (exit code $LASTEXITCODE). See output below:`n$out"
        exit $LASTEXITCODE
    }

    # Save output to file
    $out | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "Finished — output saved to $OutputFile" -ForegroundColor Green
    exit 0
} catch {
    Write-Error "Error running docker: $_"
    exit 4
}
