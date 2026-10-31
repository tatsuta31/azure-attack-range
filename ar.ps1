# Enter the azure-attack-range toolbox container.
#   .\ar.ps1                 -> interactive bash in /work/attack_range
#   .\ar.ps1 az account show -> run one command and exit
#   .\ar.ps1 -Build          -> (re)build the image first
# No [Parameter()] attributes on purpose: they turn this into an advanced script
# with common parameters, and az flags like "-o" then collide with -OutVariable/-OutBuffer.
# Everything that is not -Build stays in $args and is passed to the container as-is.
param(
    [switch]$Build
)
$Cmd = $args

$ErrorActionPreference = 'Stop'
$root  = $PSScriptRoot
$image = 'azure-attack-range:local'

if ($Build -or -not (docker image ls -q $image)) {
    docker build -t $image -f "$root\docker\Dockerfile" $root
    if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
}

# Named volumes keep az login and SSH keys on a Linux filesystem
# (bind-mounted Windows files show up as 0777 and ssh rejects such keys).
$dockerArgs = @(
    'run', '--rm', '-it',
    '-v', "${root}:/work",
    '-v', 'aar-azure:/root/.azure',
    '-v', 'aar-ssh:/root/.ssh',
    '-w', '/work/attack_range'
)
# Service principal credentials (ARM_*) for Terraform / docker/sp-login.sh. See .env.example.
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) { $dockerArgs += @('--env-file', $envFile) }
$dockerArgs += $image
if ($Cmd) { $dockerArgs += $Cmd }
& docker @dockerArgs
