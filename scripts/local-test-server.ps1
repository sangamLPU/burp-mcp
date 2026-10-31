$ErrorActionPreference = 'Stop'
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 8000)
$listener.Start()
Write-Host 'Local test server listening on http://127.0.0.1:8000/ (Ctrl+C to stop).'

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII, $false, 1024, $true)
            $null = $reader.ReadLine()
            while ($true) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrEmpty($line)) { break }
            }

            $body = [System.Text.Encoding]::UTF8.GetBytes('Burp MCP local test endpoint')
            $headers = [System.Text.Encoding]::ASCII.GetBytes(
                "HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
            )
            $stream.Write($headers, 0, $headers.Length)
            $stream.Write($body, 0, $body.Length)
            $stream.Flush()
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
}
