$ErrorActionPreference = 'Stop'
$trainerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $trainerDir

$existingTrainer = Get-Process -Name 'Anno1800MemoryTrainer' -ErrorAction SilentlyContinue
if ($existingTrainer) {
    throw 'Another Anno1800MemoryTrainer.exe is still running. Close every old trainer window before starting this version.'
}

Write-Host 'Starting the memory trainer as administrator. It reads the newest save itself to find your islands.'
$trainerProcess = Start-Process -FilePath (Join-Path $trainerDir 'Anno1800MemoryTrainer.exe') -WorkingDirectory $trainerDir -ArgumentList '--launched' -Verb RunAs -Wait -PassThru
if ($trainerProcess.ExitCode -ne 0) {
    throw "Trainer exited with code $($trainerProcess.ExitCode). Read $(Join-Path $trainerDir 'trainer.log') for the exact error."
}
