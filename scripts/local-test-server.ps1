param(
    [string]$LogPath = (Join-Path $PSScriptRoot '..\build\live-test-server-observations.jsonl')
)

$ErrorActionPreference = 'Stop'
$LogPath = [System.IO.Path]::GetFullPath($LogPath)
$logDirectory = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

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
            $path = ($requestParts[1] -split '\?', 2)[0]
            $requestHeaders = @{}
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
            if ($contentLength -gt 0) {
                $characters = New-Object char[] $contentLength
                $totalRead = 0
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
            $record = [ordered]@{
                receivedAt = [DateTimeOffset]::Now.ToString('o')
                method = $method
                path = $path
                contentLength = $contentLength
                bodyByteLength = [System.Text.Encoding]::UTF8.GetByteCount($requestBody)
                postBodyVerified = $postBodyVerified
                testCookieVerified = $testCookieVerified
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
