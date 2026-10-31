param(
    [string]$LogPath = (Join-Path $PSScriptRoot '..\build\live-test-server-observations.jsonl')
)

$ErrorActionPreference = 'Stop'
$LogPath = [System.IO.Path]::GetFullPath($LogPath)
$logDirectory = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

function Get-ConcurrentFormVerification {
    param(
        [string]$Path,
        [string]$ContentTypeHeader,
        [string]$Body,
        [int]$RequestContentLength,
        [int]$BytesRead
    )

    $contentTypeVerified = $false
    if (-not [string]::IsNullOrWhiteSpace($ContentTypeHeader)) {
        $mediaType = ($ContentTypeHeader -split ';', 2)[0].Trim()
        $contentTypeVerified = $mediaType -ieq 'application/x-www-form-urlencoded'
    }

    $fields = @{}
    $duplicateFields = $false
    $malformedField = $false
    $pairs = $Body.Split('&')
    foreach ($pair in $pairs) {
        $parts = $pair.Split('=', 2)
        if ($parts.Length -ne 2) {
            $malformedField = $true
            continue
        }
        $key = [Uri]::UnescapeDataString($parts[0].Replace('+', ' '))
        $value = [Uri]::UnescapeDataString($parts[1].Replace('+', ' '))
        if ($fields.ContainsKey($key)) {
            $duplicateFields = $true
        }
        $fields[$key] = $value
    }

    $expectedIdPattern = ''
    $expectedTestValue = ''
    $expectedName = ''
    $expectedMarker = ''
    if ($Path -eq '/test-concurrent-a') {
        $expectedIdPattern = '^phase3-A-[0-9a-f]{32}$'
        $expectedTestValue = 'alpha-modified'
        $expectedName = 'case-A'
        $expectedMarker = 'keep-A'
    } elseif ($Path -eq '/test-concurrent-b') {
        $expectedIdPattern = '^phase3-B-[0-9a-f]{32}$'
        $expectedTestValue = 'beta-modified'
        $expectedName = 'case-B'
        $expectedMarker = 'keep-B'
    }

    $testId = ''
    if ($fields.ContainsKey('test_id')) { $testId = $fields['test_id'] }
    $testIdVerified = ($expectedIdPattern -ne '' -and $testId -match $expectedIdPattern)
    $mcpTestModified = ($fields.ContainsKey('mcp_test') -and $fields['mcp_test'] -eq $expectedTestValue)
    $nameFieldPreserved = ($fields.ContainsKey('name') -and $fields['name'] -eq $expectedName)
    $markerFieldPreserved = ($fields.ContainsKey('marker') -and $fields['marker'] -eq $expectedMarker)
    $fieldSetVerified = (
        $fields.Count -eq 4 -and
        $pairs.Length -eq 4 -and
        -not $duplicateFields -and
        -not $malformedField -and
        $fields.ContainsKey('test_id') -and
        $fields.ContainsKey('mcp_test') -and
        $fields.ContainsKey('name') -and
        $fields.ContainsKey('marker')
    )
    $requestContentLengthMatchesBody = (
        $RequestContentLength -eq [System.Text.Encoding]::UTF8.GetByteCount($Body) -and
        $BytesRead -eq $RequestContentLength
    )
    $serverVerified = (
        $contentTypeVerified -and
        $fieldSetVerified -and
        $testIdVerified -and
        $mcpTestModified -and
        $nameFieldPreserved -and
        $markerFieldPreserved -and
        $requestContentLengthMatchesBody
    )

    [pscustomobject]@{
        Path = $Path
        TestId = $testId
        TestIdVerified = $testIdVerified
        McpTestModified = $mcpTestModified
        NameFieldPreserved = $nameFieldPreserved
        MarkerFieldPreserved = $markerFieldPreserved
        FieldCount = $pairs.Length
        ContentTypeVerified = $contentTypeVerified
        RequestContentLength = $RequestContentLength
        RequestBodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($Body)
        RequestContentLengthMatchesBody = $requestContentLengthMatchesBody
        ServerVerified = $serverVerified
    }
}

function Get-TestUploadVerification {
    param(
        [string]$ContentTypeHeader,
        [string]$Body,
        [int]$RequestContentLength,
        [int]$BytesRead,
        [string]$ExpectedFileText
    )

    $crlf = [string]([char]13) + [char]10
    $doubleCrlf = $crlf + $crlf
    $contentTypeVerified = $false
    $boundary = ''
    $boundaryMatch = [regex]::Match(
        $ContentTypeHeader,
        '(?i)(?:^|;)\s*boundary=(?:"(?<quoted>[^"]+)"|(?<plain>[^;\s]+))'
    )
    if (-not [string]::IsNullOrWhiteSpace($ContentTypeHeader)) {
        $mediaType = ($ContentTypeHeader -split ';', 2)[0].Trim()
        $contentTypeVerified = $mediaType -ieq 'multipart/form-data' -and $boundaryMatch.Success
    }
    if ($boundaryMatch.Success) {
        if ($boundaryMatch.Groups['quoted'].Success) {
            $boundary = $boundaryMatch.Groups['quoted'].Value
        } else {
            $boundary = $boundaryMatch.Groups['plain'].Value
        }
    }

    $boundaryTokenValid = $boundary -match '^[A-Za-z0-9_-]{1,70}$'
    $boundaryVerified = $false
    $partCount = 0
    $partsByName = @{}
    $duplicatePartNames = $false
    $malformedPart = $false
    if ($boundaryTokenValid) {
        $prefix = "--$boundary$crlf"
        $separator = "$crlf--$boundary$crlf"
        $closing = "$crlf--$boundary--$crlf"
        $markersValid = (
            $Body.StartsWith($prefix, [System.StringComparison]::Ordinal) -and
            $Body.EndsWith($closing, [System.StringComparison]::Ordinal)
        )
        if ($markersValid) {
            $middleLength = $Body.Length - $prefix.Length - $closing.Length
            if ($middleLength -ge 0) {
                $middle = $Body.Substring($prefix.Length, $middleLength)
                $parts = $middle.Split(
                    [string[]]@($separator),
                    [System.StringSplitOptions]::None
                )
                $partCount = $parts.Length
                $boundaryVerified = ($partCount -eq 4)
                foreach ($part in $parts) {
                    $partHeaderEnd = $part.IndexOf($doubleCrlf, [System.StringComparison]::Ordinal)
                    if ($partHeaderEnd -lt 0) {
                        $malformedPart = $true
                        continue
                    }
                    $partHeaderText = $part.Substring(0, $partHeaderEnd)
                    $partBody = $part.Substring($partHeaderEnd + $doubleCrlf.Length)
                    $disposition = [regex]::Match(
                        $partHeaderText,
                        '(?im)^Content-Disposition:\s*form-data;\s*name="(?<name>[^"]+)"(?:;\s*filename="(?<filename>[^"]*)")?\s*$'
                    )
                    if (-not $disposition.Success) {
                        $malformedPart = $true
                        continue
                    }
                    $name = $disposition.Groups['name'].Value
                    if ($partsByName.ContainsKey($name)) {
                        $duplicatePartNames = $true
                    }
                    $partContentType = ''
                    $contentTypeMatch = [regex]::Match($partHeaderText, '(?im)^Content-Type:\s*(?<type>[^\r\n]+)')
                    if ($contentTypeMatch.Success) {
                        $partContentType = $contentTypeMatch.Groups['type'].Value.Trim()
                    }
                    $partsByName[$name] = [pscustomobject]@{
                        HasFilename = $disposition.Groups['filename'].Success
                        Filename = $disposition.Groups['filename'].Value
                        ContentType = $partContentType
                        Body = $partBody
                    }
                }
            }
        }
    }

    $mcpTestModified = $false
    $nameFieldPreserved = $false
    $noteFieldPreserved = $false
    if ($partsByName.ContainsKey('mcp_test')) {
        $field = $partsByName['mcp_test']
        $mcpTestModified = (-not $field.HasFilename -and $field.Body -eq 'modified')
    }
    if ($partsByName.ContainsKey('name')) {
        $field = $partsByName['name']
        $nameFieldPreserved = (-not $field.HasFilename -and $field.Body -eq 'test')
    }
    if ($partsByName.ContainsKey('note')) {
        $field = $partsByName['note']
        $noteFieldPreserved = (-not $field.HasFilename -and $field.Body -eq 'keep-this')
    }

    $expectedFileBytes = [System.Text.Encoding]::ASCII.GetBytes($ExpectedFileText)
    $uploadedFileBytes = [byte[]]@()
    $filenameVerified = $false
    $fileContentTypeVerified = $false
    if ($partsByName.ContainsKey('file')) {
        $filePart = $partsByName['file']
        $filenameVerified = ($filePart.HasFilename -and $filePart.Filename -eq 'burp_mcp_test.txt')
        $fileContentTypeVerified = ($filePart.ContentType -ieq 'text/plain')
        $uploadedFileBytes = [System.Text.Encoding]::ASCII.GetBytes($filePart.Body)
    }
    $fileBytesMatch = ($uploadedFileBytes.Length -eq $expectedFileBytes.Length)
    if ($fileBytesMatch) {
        for ($index = 0; $index -lt $expectedFileBytes.Length; $index++) {
            if ($uploadedFileBytes[$index] -ne $expectedFileBytes[$index]) {
                $fileBytesMatch = $false
                break
            }
        }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $uploadedFileSha256 = ([BitConverter]::ToString($sha.ComputeHash($uploadedFileBytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $bodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($Body)
    $contentLengthMatchesBody = (
        $RequestContentLength -eq $bodyByteLength -and
        $BytesRead -eq $RequestContentLength
    )
    $partSetVerified = (
        $partsByName.Count -eq 4 -and
        -not $duplicatePartNames -and
        -not $malformedPart -and
        $partsByName.ContainsKey('mcp_test') -and
        $partsByName.ContainsKey('name') -and
        $partsByName.ContainsKey('note') -and
        $partsByName.ContainsKey('file')
    )
    $serverVerified = (
        $contentTypeVerified -and
        $boundaryVerified -and
        $partSetVerified -and
        $mcpTestModified -and
        $nameFieldPreserved -and
        $noteFieldPreserved -and
        $filenameVerified -and
        $fileContentTypeVerified -and
        $fileBytesMatch -and
        $contentLengthMatchesBody
    )

    [pscustomobject]@{
        ContentTypeVerified = $contentTypeVerified
        BoundaryVerified = $boundaryVerified
        PartCount = $partCount
        McpTestModified = $mcpTestModified
        NameFieldPreserved = $nameFieldPreserved
        NoteFieldPreserved = $noteFieldPreserved
        FilenameVerified = $filenameVerified
        FileContentTypeVerified = $fileContentTypeVerified
        FileByteLength = $uploadedFileBytes.Length
        FileSha256 = $uploadedFileSha256
        FileBytesMatch = $fileBytesMatch
        RequestContentLength = $RequestContentLength
        RequestBodyByteLength = $bodyByteLength
        RequestContentLengthMatchesBody = $contentLengthMatchesBody
        ServerVerified = $serverVerified
    }
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 8000)
$listener.Start()
Write-Host "Local test server listening on http://127.0.0.1:8000/ (Ctrl+C to stop). Log: $LogPath"

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII, $false, 1024, $true)
            $requestLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($requestLine)) { continue }

            $requestParts = $requestLine.Split(' ', 3)
            $method = $requestParts[0]
            $requestTarget = $requestParts[1]
            $requestHeaders = @{}
            if ($requestTarget -match '^https?://') {
                $path = ([Uri]$requestTarget).AbsolutePath
            } else {
                $path = $requestTarget.Split('?')[0]
            }
            while ($true) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrEmpty($line)) { break }
                $colon = $line.IndexOf(':')
                if ($colon -gt 0) {
                    $name = $line.Substring(0, $colon).Trim()
                    $value = $line.Substring($colon + 1).Trim()
                    $requestHeaders[$name] = $value
                }
            }

            $contentLength = 0
            if ($requestHeaders.ContainsKey('Content-Length')) {
                $parsedLength = 0
                if ([int]::TryParse($requestHeaders['Content-Length'], [ref]$parsedLength) -and $parsedLength -gt 0) {
                    $contentLength = $parsedLength
                }
            }

            $requestBody = ''
            $totalRead = 0
            if ($contentLength -gt 0) {
                $characters = New-Object char[] $contentLength
                while ($totalRead -lt $contentLength) {
                    $read = $reader.Read($characters, $totalRead, $contentLength - $totalRead)
                    if ($read -le 0) { break }
                    $totalRead += $read
                }
                if ($totalRead -gt 0) {
                    $requestBody = [string]::new($characters, 0, $totalRead)
                }
            }

            $postBodyVerified = $null
            if ($path -eq '/test-post') {
                $postBodyVerified = $false
                try {
                    $postJson = ConvertFrom-Json -InputObject $requestBody -ErrorAction Stop
                    $postBodyVerified = ($postJson.name -eq 'original' -and $postJson.mcp_test -eq 'after')
                } catch { }
            }
            $testCookieVerified = $null
            if ($path -eq '/test-cookie') {
                $testCookieVerified = $false
                if ($requestHeaders.ContainsKey('Cookie')) {
                    foreach ($cookiePair in ($requestHeaders['Cookie'] -split ';')) {
                        $parts = $cookiePair.Trim().Split('=', 2)
                        if ($parts.Length -eq 2 -and $parts[0].Trim() -eq 'mcp_test') {
                            $testCookieVerified = ($parts[1] -eq 'modified')
                            break
                        }
                    }
                }
            }
            $formNameFieldUnchanged = $null
            $formMcpTestModified = $null
            $formFieldCount = $null
            $formContentTypeVerified = $null
            $requestContentLengthMatchesBody = $null
            $formBodyVerified = $null
            if ($path -eq '/test-form') {
                $formContentTypeVerified = $false
                if ($requestHeaders.ContainsKey('Content-Type')) {
                    $formMediaType = ($requestHeaders['Content-Type'] -split ';', 2)[0].Trim()
                    $formContentTypeVerified = $formMediaType -ieq 'application/x-www-form-urlencoded'
                }
                $formPairs = $requestBody.Split('&')
                $formFields = @{}
                $formDuplicateFields = $false
                foreach ($pair in $formPairs) {
                    $parts = $pair.Split('=', 2)
                    if ($parts.Length -ne 2) {
                        $formDuplicateFields = $true
                        continue
                    }
                    $key = [Uri]::UnescapeDataString($parts[0].Replace('+', ' '))
                    $value = [Uri]::UnescapeDataString($parts[1].Replace('+', ' '))
                    if ($formFields.ContainsKey($key)) {
                        $formDuplicateFields = $true
                    }
                    $formFields[$key] = $value
                }
                $formNameFieldUnchanged = ($formFields.ContainsKey('name') -and $formFields['name'] -eq 'test')
                $formMcpTestModified = ($formFields.ContainsKey('mcp_test') -and $formFields['mcp_test'] -eq 'modified')
                $formFieldCount = $formPairs.Length
                $requestContentLengthMatchesBody = (
                    $contentLength -eq [System.Text.Encoding]::UTF8.GetByteCount($requestBody) -and
                    $totalRead -eq $contentLength
                )
                $formBodyVerified = (
                    $formFieldCount -eq 2 -and
                    $formFields.Count -eq 2 -and
                    -not $formDuplicateFields -and
                    $formNameFieldUnchanged -and
                    $formMcpTestModified -and
                    $formContentTypeVerified -and
                    $requestContentLengthMatchesBody
                )
            }
            $multipartVerification = $null
            if ($path -eq '/test-upload') {
                $contentTypeHeader = ''
                if ($requestHeaders.ContainsKey('Content-Type')) {
                    $contentTypeHeader = $requestHeaders['Content-Type']
                }
                $uploadArguments = @{
                    ContentTypeHeader = $contentTypeHeader
                    Body = $requestBody
                    RequestContentLength = $contentLength
                    BytesRead = $totalRead
                    ExpectedFileText = 'Burp MCP multipart upload test data only.'
                }
                $multipartVerification = Get-TestUploadVerification @uploadArguments
                $requestContentLengthMatchesBody = $multipartVerification.RequestContentLengthMatchesBody
            }
            $concurrentVerification = $null
            if ($path -eq '/test-concurrent-a' -or $path -eq '/test-concurrent-b') {
                $contentTypeHeader = ''
                if ($requestHeaders.ContainsKey('Content-Type')) {
                    $contentTypeHeader = $requestHeaders['Content-Type']
                }
                $concurrentArguments = @{
                    Path = $path
                    ContentTypeHeader = $contentTypeHeader
                    Body = $requestBody
                    RequestContentLength = $contentLength
                    BytesRead = $totalRead
                }
                $concurrentVerification = Get-ConcurrentFormVerification @concurrentArguments
                $requestContentLengthMatchesBody = $concurrentVerification.RequestContentLengthMatchesBody
            }
            $record = [ordered]@{
                receivedAt = [DateTimeOffset]::Now.ToString('o')
                method = $method
                path = $path
                contentLength = $contentLength
                bodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($requestBody)
                postBodyVerified = $postBodyVerified
                testCookieVerified = $testCookieVerified
                formNameFieldUnchanged = $formNameFieldUnchanged
                formMcpTestModified = $formMcpTestModified
                formFieldCount = $formFieldCount
                formContentTypeVerified = $formContentTypeVerified
                requestContentLengthMatchesBody = $requestContentLengthMatchesBody
                formBodyVerified = $formBodyVerified
                multipartContentTypeVerified = $multipartVerification.ContentTypeVerified
                multipartBoundaryVerified = $multipartVerification.BoundaryVerified
                multipartPartCount = $multipartVerification.PartCount
                multipartMcpTestModified = $multipartVerification.McpTestModified
                multipartNameFieldPreserved = $multipartVerification.NameFieldPreserved
                multipartNoteFieldPreserved = $multipartVerification.NoteFieldPreserved
                multipartFilenameVerified = $multipartVerification.FilenameVerified
                multipartFileContentTypeVerified = $multipartVerification.FileContentTypeVerified
                multipartFileByteLength = $multipartVerification.FileByteLength
                multipartFileSha256 = $multipartVerification.FileSha256
                multipartFileBytesMatch = $multipartVerification.FileBytesMatch
                multipartBodyVerified = $multipartVerification.ServerVerified
                concurrentTestId = $concurrentVerification.TestId
                concurrentTestIdVerified = $concurrentVerification.TestIdVerified
                concurrentMcpTestModified = $concurrentVerification.McpTestModified
                concurrentNameFieldPreserved = $concurrentVerification.NameFieldPreserved
                concurrentMarkerFieldPreserved = $concurrentVerification.MarkerFieldPreserved
                concurrentFieldCount = $concurrentVerification.FieldCount
                concurrentContentTypeVerified = $concurrentVerification.ContentTypeVerified
                concurrentContentLengthMatchesBody = $concurrentVerification.RequestContentLengthMatchesBody
                concurrentBodyVerified = $concurrentVerification.ServerVerified
            }
            $recordJson = ConvertTo-Json -InputObject $record -Compress -Depth 4
            [System.IO.File]::AppendAllText($LogPath, $recordJson + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

            $status = '200 OK'
            $contentType = 'text/plain; charset=utf-8'
            $extraHeaders = @()
            switch ($path) {
                '/live-check' {
                    $responseBody = 'Burp MCP local test endpoint'
                }
                '/test-form' {
                    $contentType = 'application/json; charset=utf-8'
                    $formResult = [ordered]@{
                        method = $method
                        path = $path
                        requestContentLength = $contentLength
                        requestBodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($requestBody)
                        nameFieldUnchanged = $formNameFieldUnchanged
                        mcpTestModified = $formMcpTestModified
                        formFieldCount = $formFieldCount
                        formContentTypeVerified = $formContentTypeVerified
                        requestContentLengthMatchesBody = $requestContentLengthMatchesBody
                        serverVerified = $formBodyVerified
                    }
                    $responseBody = ConvertTo-Json -InputObject $formResult -Compress -Depth 4
                }
                '/test-upload' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject $multipartVerification -Compress -Depth 4
                }
                '/test-concurrent-a' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject $concurrentVerification -Compress -Depth 4
                }
                '/test-concurrent-b' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = ConvertTo-Json -InputObject $concurrentVerification -Compress -Depth 4
                }
                '/test-post' {
                    $contentType = 'application/json; charset=utf-8'
                    $responseBody = $requestBody
                }
                '/test-cookie' {
                    $responseBody = 'Dedicated test cookie recorded by local server'
                }
                '/test-set-cookie' {
                    $extraHeaders += 'Set-Cookie: mcp_test=original; Path=/; SameSite=Lax'
                    $responseBody = 'Dedicated Set-Cookie test response'
                }
                '/test-html' {
                    $contentType = 'text/html; charset=utf-8'
                    $responseBody = '<!doctype html><html><head><title>Burp MCP HTML Test</title></head><body><p>Preserve this paragraph.</p><h1>Original Page</h1></body></html>'
                }
                default {
                    $status = '404 Not Found'
                    $responseBody = 'Not found'
                }
            }

            $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
            $crlf = [string]([char]13) + [char]10
            $responseHeaderLines = New-Object 'System.Collections.Generic.List[string]'
            $responseHeaderLines.Add("HTTP/1.1 $status")
            $responseHeaderLines.Add("Content-Type: $contentType")
            foreach ($header in $extraHeaders) { $responseHeaderLines.Add($header) }
            $responseHeaderLines.Add("Content-Length: $($bodyBytes.Length)")
            $responseHeaderLines.Add('Connection: close')
            $responseHeaderBytes = [System.Text.Encoding]::ASCII.GetBytes(([string]::Join($crlf, $responseHeaderLines.ToArray()) + $crlf + $crlf))

            $stream.Write($responseHeaderBytes, 0, $responseHeaderBytes.Length)
            $stream.Write($bodyBytes, 0, $bodyBytes.Length)
            $stream.Flush()
        } catch {
            Write-Warning "Local test request failed: $($_.Exception.Message)"
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
}
