$ErrorActionPreference = 'Stop'

$orchestratorPath = Join-Path $PSScriptRoot 'run-full-validation.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($orchestratorPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "Full validation orchestrator does not parse: $($parseErrors[0].Message)"
}

$functionAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-GradleValidationArguments'
}, $true)
if ($null -eq $functionAst) { throw 'Get-GradleValidationArguments was not found in the orchestrator.' }
. ([scriptblock]::Create($functionAst.Extent.Text))

$defaultOffline = Get-GradleValidationArguments -ValidationMode OFFLINE -ToolchainVersion 17
if ($defaultOffline -notmatch '^-?test ' -or $defaultOffline -notmatch ' -x shadowJar$') {
    throw 'Default OFFLINE Gradle plan must run tests while excluding shadowJar.'
}
if ($defaultOffline -notmatch '--offline' -or $defaultOffline -notmatch 'validation\.mode=offline') {
    throw 'Default OFFLINE Gradle plan must remain offline and select the offline test tag set.'
}

$localPlan = Get-GradleValidationArguments -ValidationMode LOCAL -ToolchainVersion 18
if ($localPlan -notmatch 'validation\.mode=all' -or $localPlan -notmatch ' -x shadowJar$') {
    throw 'LOCAL validation must include loopback-tagged JVM tests without packaging a new JAR.'
}

$candidatePlan = Get-GradleValidationArguments -ValidationMode OFFLINE -ToolchainVersion 17 -BuildCandidate
if ($candidatePlan -match ' -x shadowJar(?:\s|$)') {
    throw 'Explicit candidate packaging must leave shadowJar enabled.'
}

$scriptText = [System.IO.File]::ReadAllText($orchestratorPath)
if ($scriptText -notmatch '\[switch\]\$BuildCandidate' -or
    $scriptText -notmatch '\$BuildCandidate\s+-and\s+\(Test-Path' -or
    $scriptText -notmatch 'if\s*\(\$BuildCandidate\)\s*\{\s*\$candidateDir') {
    throw 'JAR backup and candidate copy must both be guarded by the explicit BuildCandidate switch.'
}

Write-Host 'PASS: 5 validation-orchestrator assertions; default tests preserve the existing JAR, and packaging requires explicit opt-in.'
