# ============================================================
#  VigilKit 构建与自测
#
#  用法：
#    pwsh -File build.ps1            # 编译 + 跑测试
#    pwsh -File build.ps1 -TestOnly  # 只跑测试
#    pwsh -File build.ps1 -UseDotnet # 走 dotnet SDK
# ============================================================
[CmdletBinding()]
param(
    [switch]$TestOnly,
    [switch]$UseDotnet
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Die($m)  { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

$buildDir = Join-Path $root "build"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$libraryDll = Join-Path $buildDir "VigilKit.dll"
$testExe    = Join-Path $buildDir "VigilKit.Tests.exe"

# ---------- 定位编译器 ----------
$cscCandidates = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)
$csc = $null
foreach ($c in $cscCandidates) { if (Test-Path $c) { $csc = $c; break } }

if (-not $csc) {
    Die "找不到 .NET Framework 的 csc.exe。请安装 .NET Framework 4.x，或改用 -UseDotnet"
}

# ---------- 公共编译参数 ----------
$refs = @(
    "/r:System.dll",
    "/r:System.Core.dll",
    "/r:System.IO.Compression.dll"
)
$common = @("/nologo", "/langversion:5", "/optimize+", "/warn:4")

# ---------- 日志 ----------
# 编译与测试的输出同时落盘，便于在无人值守环境（CI）里事后排查。
$envLog   = Join-Path $buildDir "env.log"
$buildLog = Join-Path $buildDir "build.log"
$testLog  = Join-Path $buildDir "selftest.log"

$envLines = @(
    "=== VigilKit 构建环境 ==="
    "时间                : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
    "PowerShell 版本     : $($PSVersionTable.PSVersion)"
    "输出是否被重定向    : $([Console]::IsOutputRedirected)"
    "执行策略            : $(Get-ExecutionPolicy)"
    "当前目录            : $PWD"
    "项目根目录          : $root"
    "编译器              : $csc"
    "编译器是否存在      : $(Test-Path $csc)"
    "源文件数            : $((Get-ChildItem -Path (Join-Path $root 'src\VigilKit') -Recurse -Filter *.cs).Count)"
)
$envLines | Out-File -FilePath $envLog -Encoding UTF8

if (-not $TestOnly) {

    Info "编译 VigilKit 库"
    $libSources = Get-ChildItem -Path (Join-Path $root "src\VigilKit") -Recurse -Filter *.cs |
                  ForEach-Object { $_.FullName }
    if ($libSources.Count -eq 0) { Die "src\VigilKit 下没有源文件" }

    $libArgs = @($common) + $refs + @("/target:library", "/out:$libraryDll") + $libSources
    & $csc $libArgs 2>&1 | Tee-Object -FilePath $buildLog
    if ($LASTEXITCODE -ne 0) { Die "库编译失败（详见 $buildLog）" }
    Ok ("VigilKit.dll 已生成: {0:N0} 字节" -f (Get-Item $libraryDll).Length)

    Info "编译测试程序"
    $testSources = Get-ChildItem -Path (Join-Path $root "tests") -Filter *.cs |
                   ForEach-Object { $_.FullName }

    $testArgs = @($common) + $refs + @(
        "/r:$libraryDll", "/target:exe", "/out:$testExe"
    ) + $testSources
    & $csc $testArgs 2>&1 | Tee-Object -FilePath $buildLog -Append
    if ($LASTEXITCODE -ne 0) { Die "测试程序编译失败（详见 $buildLog）" }
    Ok ("VigilKit.Tests.exe 已生成: {0:N0} 字节" -f (Get-Item $testExe).Length)
}

if (-not (Test-Path $testExe)) { Die "找不到测试程序，请先完整构建（去掉 -TestOnly）" }

# ---------- 运行测试 ----------
Write-Host ""
Info "运行自测"
Write-Host ""
& $testExe 2>&1 | Tee-Object -FilePath $testLog
$exitCode = $LASTEXITCODE

Write-Host ""
if ($exitCode -eq 0) {
    Ok "自测通过"
} else {
    Write-Host "[x] 自测失败（退出码 $exitCode）" -ForegroundColor Red
}
exit $exitCode