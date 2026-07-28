param([switch]$SkipInstaller)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
python -m PyInstaller --noconfirm --clean packaging\ChildSafeService.spec
python -m PyInstaller --noconfirm --clean packaging\ChildSafe.spec
if (-not $SkipInstaller) {
    $Compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if (-not $Compiler) {
        $Candidates = @(
            "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        )
        $Compiler = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $Compiler) { throw 'Inno Setup 6 is required to build the installer.' }
    & $Compiler packaging\ChildSafe.iss
}