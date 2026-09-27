# 重新编译 Anno1800MemoryTrainer.exe。
# 与发布版一致：x64、优化、内嵌 trainer.manifest（requireAdministrator）。
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = 'Stop'
$trainerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $trainerDir

if (Get-Process -Name 'Anno1800MemoryTrainer' -ErrorAction SilentlyContinue) {
    throw '修改器正在运行，先关闭它的窗口再重新编译。'
}

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) {
    throw "找不到 csc.exe：$csc（需要 .NET Framework 4.x 自带的 C# 编译器）。"
}

& $csc /nologo /target:exe /platform:x64 /optimize+ /codepage:65001 /win32manifest:trainer.manifest `
    /out:Anno1800MemoryTrainer.exe Anno1800MemoryTrainer.cs
if ($LASTEXITCODE -ne 0) { throw "编译失败，退出码 $LASTEXITCODE。" }

Get-Item Anno1800MemoryTrainer.exe | Select-Object FullName, Length, LastWriteTime
