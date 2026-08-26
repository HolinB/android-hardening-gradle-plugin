$ErrorActionPreference = "Stop"
$launcherRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
try {
    $javaVersionOutput = (& java -version 2>&1 | Out-String)
} catch {
    [Console]::Error.WriteLine("hardeningw: JDK 17 or newer is required")
    exit 2
}
if ($javaVersionOutput -match 'version\s+"1\.([0-9]+)' ) {
    $javaMajor = [int]$matches[1]
} elseif ($javaVersionOutput -match 'version\s+"([0-9]+)' ) {
    $javaMajor = [int]$matches[1]
} else {
    [Console]::Error.WriteLine("hardeningw: JDK 17 or newer is required")
    exit 2
}
if ($javaMajor -lt 17) {
    [Console]::Error.WriteLine("hardeningw: JDK 17 or newer is required")
    exit 2
}
& java "-Dhardening.launcher.source=$launcherRoot" "$launcherRoot/bootstrap/HardeningLauncher.java" @args
exit $LASTEXITCODE
