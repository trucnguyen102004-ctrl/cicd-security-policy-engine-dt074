<#
DT074 Security Gate - local runner for Windows + Docker Desktop (WSL2 backend).

  .\run_local.ps1 setup        # build pinned image, download Juliet, build dataset + manifest
  .\run_local.ps1 demo         # Demo 1 (blocked) + Demo 2 (passes)
  .\run_local.ps1 experiment   # 3 runs x {isolated, realistic} x {main, holdout}, seed 42
  .\run_local.ps1 ablation     # adaptive minus one mechanism at a time
  .\run_local.ps1 scale        # repo-size scalability study
  .\run_local.ps1 analyze exp1-main   # tables + charts for results\exp1-main
  .\run_local.ps1 test         # unit / integration / negative tests
  .\run_local.ps1 gate         # run the adaptive gate on this repo (HEAD~1..HEAD)

If PowerShell blocks the script:  Set-ExecutionPolicy -Scope Process Bypass
#>
param(
    [Parameter(Position = 0)][string]$Task = "help",
    [Parameter(Position = 1)][string]$Arg = ""
)
$ErrorActionPreference = "Stop"
$Image = "security-gate:1.0"
$Root = $PSScriptRoot

$Docker = (Get-Command docker -ErrorAction SilentlyContinue).Source
if (-not $Docker) {
    $cand = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe"
    if (Test-Path $cand) { $Docker = $cand } else { throw "docker not found - start Docker Desktop first" }
}

function Invoke-Gate([string[]]$Cmd) {
    # /src = this repository; the frozen Semgrep rules + Trivy DB live inside the image
    & $Docker run --rm -e GATE_REGISTRY=/opt/gate/rules/registry -v "${Root}:/src" -w /src `
        --entrypoint $Cmd[0] $Image $Cmd[1..($Cmd.Length - 1)]
    if ($LASTEXITCODE -ne 0 -and $Task -notin @("demo", "gate")) { throw "failed: $($Cmd -join ' ')" }
}

switch ($Task) {
    "setup" {
        python "$Root\scripts\setup_tools.py"
        python "$Root\scripts\setup_fixtures.py"
    }
    "demo"       { Invoke-Gate @("bash", "/src/scripts/demo.sh") }
    "experiment" { Invoke-Gate @("python", "/src/scripts/run_experiment.py", "--runs", "3", "--seed", "42",
                                 "--profiles", "isolated,realistic", "--splits", "main,holdout",
                                 "--out", "/src/results/exp1-main") }
    "ablation"   { Invoke-Gate @("python", "/src/scripts/run_experiment.py", "--runs", "3", "--seed", "42",
                                 "--ablation", "--profiles", "isolated,realistic", "--splits", "main,holdout",
                                 "--variants", "baseline,adaptive,adaptive-no_differential,adaptive-no_language_aware,adaptive-no_custom_rules,adaptive-no_risk_threshold,adaptive-no_sanitizer_triage,adaptive-no_sca_triage",
                                 "--out", "/src/results/exp2-ablation") }
    "scale"      { Invoke-Gate @("python", "/src/scripts/run_experiment.py", "--runs", "3", "--seed", "42",
                                 "--profiles", "realistic", "--scale", "0,10,40", "--variants", "baseline,adaptive",
                                 "--cases", "J01-bad,J01-good,P01-bad,P01-good,S01-bad,S03-good",
                                 "--out", "/src/results/exp3-scale") }
    "analyze"    { python "$Root\scripts\analyze.py" "$Root\results\$Arg" --charts }   # host: pip install -r requirements-dev.txt
esults\$Arg" --charts }   # host: pip install -r requirements-dev.txt
esults\$Arg" --charts }   # host: pip install -r requirements-dev.txt
    "test"       { Invoke-Gate @("python", "-m", "unittest", "discover", "-s", "/src/tests", "-v") }
    "gate"       { Invoke-Gate @("python", "/src/gate/cli.py", "--mode", "adaptive", "--repo", "/src",
                                 "--base", "HEAD~1", "--out", "/src/.gate-out") }
    default      { Get-Help $MyInvocation.MyCommand.Path -Detailed | Out-Host; Get-Content $PSCommandPath -TotalCount 16 | Select-Object -Skip 1 }
}
