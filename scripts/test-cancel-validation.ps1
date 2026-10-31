$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cancel-test-validation.ps1')

function New-HttpTestBytes([string]$Text) {
    return ,([System.Text.Encoding]::ASCII.GetBytes($Text))
}

function Assert-Outcome {
    param(
        [string]$Name,
        [byte[]]$Bytes,
        [string]$Termination,
        [string]$ExpectedOutcome,
        [int]$ExpectedServerCount = 0,
        [object]$ExpectedStatusCode = $null,
        [bool]$ExpectedPass
    )
    $observation = Get-CancelClientObservation -ResponseBytes $Bytes -Termination $Termination
    if ($observation.Outcome -ne $ExpectedOutcome) {
        throw "${Name}: expected outcome $ExpectedOutcome, observed $($observation.Outcome)."
    }
    if ($null -ne $ExpectedStatusCode -and $observation.HttpStatusCode -ne [int]$ExpectedStatusCode) {
        throw "${Name}: expected status $ExpectedStatusCode, observed $($observation.HttpStatusCode)."
    }
    $validation = Test-CancelInterceptionObservation -ClientOutcome $observation.Outcome -ClientStatusCode $observation.HttpStatusCode -ServerRequestCount $ExpectedServerCount
    if ($validation.Passed -ne $ExpectedPass) {
        throw "${Name}: validation pass state mismatch; failed conditions: $($validation.FailedConditions -join ', ')."
    }
    return $observation
}

$empty = [byte[]]@()
$eof = Assert-Outcome -Name 'EmptyEof' -Bytes $empty -Termination EOF -ExpectedOutcome EOFWithoutResponse -ExpectedPass $true
$reset = Assert-Outcome -Name 'EmptyReset' -Bytes $empty -Termination ConnectionReset -ExpectedOutcome ConnectionReset -ExpectedPass $true
$aborted = Assert-Outcome -Name 'EmptyAbort' -Bytes $empty -Termination ConnectionAborted -ExpectedOutcome ConnectionAborted -ExpectedPass $true

$completeError = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 4`r`nConnection: close`r`n`r`nnope"
$httpError = Assert-Outcome -Name 'CompleteHttpError' -Bytes $completeError -Termination Open -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 502 -ExpectedPass $true
if ($httpError.ExpectedBodyBytes -ne 4 -or $httpError.BodyBytesObserved -ne 4 -or $httpError.Framing -ne 'Content-Length') {
    throw 'CompleteHttpError: content-length framing was not fully verified.'
}

$completeSuccess = New-HttpTestBytes "HTTP/1.1 200 OK`r`nContent-Length: 0`r`n`r`n"
$httpSuccess = Assert-Outcome -Name 'UnexpectedSuccessResponse' -Bytes $completeSuccess -Termination Open -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 200 -ExpectedPass $false

$oneByteHeader = New-HttpTestBytes 'H'
$partialTimeout = Assert-Outcome -Name 'OneByteThenTimeout' -Bytes $oneByteHeader -Termination ReadTimeout -ExpectedOutcome PartialHttpResponseTimeout -ExpectedPass $false
if ($partialTimeout.BytesObserved -ne 1) { throw 'OneByteThenTimeout: expected exactly one observed byte.' }
$partialEofHeader = Assert-Outcome -Name 'OneByteThenEof' -Bytes $oneByteHeader -Termination EOF -ExpectedOutcome PartialHttpResponseEOF -ExpectedPass $false
$partialReset = Assert-Outcome -Name 'OneByteThenReset' -Bytes $oneByteHeader -Termination ConnectionReset -ExpectedOutcome PartialHttpResponseConnectionReset -ExpectedPass $false
$partialAbort = Assert-Outcome -Name 'OneByteThenAbort' -Bytes $oneByteHeader -Termination ConnectionAborted -ExpectedOutcome PartialHttpResponseConnectionAborted -ExpectedPass $false

$partialBody = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 10`r`n`r`nbad"
$partialEof = Assert-Outcome -Name 'PartialBodyEof' -Bytes $partialBody -Termination EOF -ExpectedOutcome PartialHttpResponseEOF -ExpectedStatusCode 502 -ExpectedPass $false
if ($partialEof.ExpectedBodyBytes -ne 10 -or $partialEof.BodyBytesObserved -ne 3) {
    throw 'PartialBodyEof: partial Content-Length framing was not reported accurately.'
}

$emptyTimeout = Assert-Outcome -Name 'EmptyTimeout' -Bytes $empty -Termination ReadTimeout -ExpectedOutcome ReadTimeout -ExpectedPass $false
$invalidData = New-HttpTestBytes 'X'
$nonHttp = Assert-Outcome -Name 'NonHttpData' -Bytes $invalidData -Termination EOF -ExpectedOutcome NonHttpData -ExpectedPass $false

$closeDelimited = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nConnection: close`r`n`r`nerror"
$closeResponse = Assert-Outcome -Name 'CloseDelimitedError' -Bytes $closeDelimited -Termination EOF -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 502 -ExpectedPass $true
if ($closeResponse.Framing -ne 'CloseDelimited') { throw 'CloseDelimitedError: expected close-delimited response framing.' }

$chunked = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nTransfer-Encoding: chunked`r`n`r`n4`r`nnope`r`n0`r`n`r`n"
$chunkedResponse = Assert-Outcome -Name 'CompleteChunkedError' -Bytes $chunked -Termination Open -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 502 -ExpectedPass $true
if ($chunkedResponse.Framing -ne 'Chunked') { throw 'CompleteChunkedError: expected chunked response framing.' }

$ambiguousFraming = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 4`r`nTransfer-Encoding: chunked`r`n`r`n4`r`nnope`r`n0`r`n`r`n"
$invalidResponse = Assert-Outcome -Name 'ConflictingFraming' -Bytes $ambiguousFraming -Termination EOF -ExpectedOutcome InvalidHttpResponse -ExpectedPass $false

$originReached = Test-CancelInterceptionObservation -ClientOutcome $httpError.Outcome -ClientStatusCode $httpError.HttpStatusCode -ServerRequestCount 1
if ($originReached.Passed -or $originReached.FailedConditions -notcontains 'OriginDidNotReceiveRequest') {
    throw 'OriginRequestDetected: a server observation must fail no-origin-receive validation.'
}

$timeoutSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::TimedOut)
$resetSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionReset)
$abortSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionAborted)
$otherSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::HostNotFound)
if ((Get-CancelSocketTermination -Exception ([System.IO.IOException]::new('synthetic timeout', $timeoutSocket))) -ne 'ReadTimeout') {
    throw 'SocketTimeoutMapping: IOException-wrapped timeout was not identified.'
}
if ((Get-CancelSocketTermination -Exception ([System.IO.IOException]::new('synthetic reset', $resetSocket))) -ne 'ConnectionReset') {
    throw 'SocketResetMapping: IOException-wrapped reset was not identified.'
}
if ((Get-CancelSocketTermination -Exception $abortSocket) -ne 'ConnectionAborted') {
    throw 'SocketAbortMapping: direct abort was not identified.'
}
if ((Get-CancelSocketTermination -Exception $otherSocket) -ne 'SocketError') {
    throw 'OtherSocketMapping: unclassified socket error was not kept distinct.'
}
if ((Get-CancelSocketTermination -Exception ([System.IO.IOException]::new('synthetic read error'))) -ne 'ReadError') {
    throw 'ReadErrorMapping: non-socket I/O failure was not kept distinct.'
}

[pscustomobject]@{
    EmptyEof = 'PASS'
    EmptyReset = 'PASS'
    EmptyAbort = 'PASS'
    CompleteHttpError = 'PASS'
    UnexpectedSuccessResponseRejected = 'PASS'
    OneBytePartialTimeout = 'PASS'
    OneBytePartialEofResetAbort = 'PASS'
    PartialBodyEof = 'PASS'
    EmptyTimeout = 'PASS'
    NonHttpData = 'PASS'
    CloseDelimitedError = 'PASS'
    CompleteChunkedError = 'PASS'
    ConflictingFramingRejected = 'PASS'
    ServerRequestDetected = 'PASS'
    SocketExceptionMapping = 'PASS'
    NetworkRequestsSent = 0
} | Format-List
