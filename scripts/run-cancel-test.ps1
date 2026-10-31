$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cancel-test-validation.ps1')

$proxyHost = '127.0.0.1'
$proxyPort = 8080
$targetHost = '127.0.0.1'
$targetPort = 8000
$targetPath = '/test-cancel'
$targetUrl = "http://$targetHost`:$targetPort$targetPath"
$testId = 'phase4a-' + [Guid]::NewGuid().ToString('N')
$crlf = [string]([char]13) + [char]10
$logPath = Join-Path $PSScriptRoot '..\build\live-test-server-observations.jsonl'

$baselineLines = @()
if (Test-Path -LiteralPath $logPath -PathType Leaf) {
    $baselineLines = @(Get-Content -LiteralPath $logPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

$requestText = @(
    "GET $targetUrl HTTP/1.1"
    "Host: $targetHost`:$targetPort"
    "X-MCP-Test-ID: $testId"
    'Connection: close'
    ''
    ''
) -join $crlf
$requestBytes = [System.Text.Encoding]::ASCII.GetBytes($requestText)
$client = [System.Net.Sockets.TcpClient]::new()
$client.SendTimeout = 10000
$client.ReceiveTimeout = 125000
$clientOutcome = 'NotSent'
$clientBytesObserved = 0
$clientObservation = $null
$readTermination = 'Open'
$responseMemory = [System.IO.MemoryStream]::new()

try {
    $connectTask = $client.ConnectAsync($proxyHost, $proxyPort)
    if (-not $connectTask.Wait(10000)) {
        throw 'Timed out connecting to local Burp Proxy; request was not sent and will not be retried.'
    }
    $null = $connectTask.GetAwaiter().GetResult()
    $stream = $client.GetStream()
    $stream.Write($requestBytes, 0, $requestBytes.Length)
    $stream.Flush()

    [pscustomobject]@{
        State = 'Request sent once; leave this PowerShell process running while the held request is dropped in Burp.'
        Target = $targetUrl
        Proxy = "$proxyHost`:$proxyPort"
        TestId = $testId
        AutomaticRetries = $false
        ReceiveDeadlineSeconds = 125
    } | Format-List

    $buffer = New-Object byte[] 4096
    $readClock = [System.Diagnostics.Stopwatch]::StartNew()
    $readDeadlineMilliseconds = 125000
    while ($true) {
        $remainingMilliseconds = $readDeadlineMilliseconds - [int]$readClock.ElapsedMilliseconds
        if ($remainingMilliseconds -le 0) {
            $readTermination = 'ReadTimeout'
            break
        }
        $client.ReceiveTimeout = $remainingMilliseconds
        try {
            $readCount = $stream.Read($buffer, 0, $buffer.Length)
        } catch {
            $readTermination = Get-CancelSocketTermination -Exception $_.Exception
            break
        }
        if ($readCount -eq 0) {
            $readTermination = 'EOF'
            break
        }
        $clientBytesObserved += $readCount
        if (($responseMemory.Length + $readCount) -gt 1048576) {
            $readTermination = 'ResponseTooLarge'
            break
        }
        $responseMemory.Write($buffer, 0, $readCount)
        $clientObservation = Get-CancelClientObservation -ResponseBytes $responseMemory.ToArray() -Termination Open
        if ($clientObservation.Outcome -notin @('NoDataYet', 'ResponseInProgress')) {
            break
        }
    }
    $clientObservation = Get-CancelClientObservation -ResponseBytes $responseMemory.ToArray() -Termination $readTermination
    $clientOutcome = $clientObservation.Outcome

    $allLines = @()
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        $allLines = @(Get-Content -LiteralPath $logPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $newLines = @($allLines | Select-Object -Skip $baselineLines.Count)
    $newRecords = @($newLines | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
    $serverRecords = @($newRecords | Where-Object { $_.path -eq $targetPath })
    $matchingIdRecords = @($serverRecords | Where-Object { $_.cancellationTestId -eq $testId })
    $serverVerified = ($matchingIdRecords.Count -eq 1 -and $matchingIdRecords[0].cancellationRequestVerified -eq $true)
    $validation = Test-CancelInterceptionObservation -ClientOutcome $clientOutcome -ClientStatusCode $clientObservation.HttpStatusCode -ServerRequestCount $serverRecords.Count

    [pscustomobject]@{
        ClientOriginEvidence = if ($validation.Passed) { 'PASS' } else { 'FAIL' }
        ClientOutcome = $clientOutcome
        ClientBytesObserved = $clientBytesObserved
        ClientHttpStatusCode = $clientObservation.HttpStatusCode
        ClientFraming = $clientObservation.Framing
        ClientExpectedBodyBytes = $clientObservation.ExpectedBodyBytes
        ClientBodyBytesObserved = $clientObservation.BodyBytesObserved
        ServerRequestsToTestPath = $serverRecords.Count
        MatchingTestIdRecords = $matchingIdRecords.Count
        ServerVerifiedIfReached = $serverVerified
        FailedConditions = ($validation.FailedConditions -join ', ')
        AutomaticRetries = $false
    } | Format-List

    if (-not $validation.Passed) {
        throw "Cancellation client/origin evidence failed: $($validation.FailedConditions -join ', '). The request was sent once; do not retry it."
    }
} finally {
    $responseMemory.Dispose()
    $client.Dispose()
}
