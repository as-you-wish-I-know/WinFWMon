# Traffic generator — WinFWMon testing aid.
#
# Opens short-lived outbound TCP connections in a loop to produce a STEADY,
# DENSE stream of Windows Filtering Platform connection events (5156) so you can
# watch WinFWMon surface live events without waiting for incidental traffic. TCP
# connections are logged far more reliably per-event than ICMP (ping), which
# Windows under-logs.
#
# Run this in a SEPARATE elevated window while WinFWMon (or a diagnostic) is
# running, then stop it with Ctrl+C when done.
#
# It connects to 8.8.8.8:53 (Google public DNS — built for high request volume)
# a few times per second. This is read-only network probing; it sends no data.
# To avoid sustained external connections you can point $target at a LAN address
# (e.g. your router) — the WFP event fires on the local connection attempt
# regardless of the destination.

$target = '8.8.8.8'
$port = 53
$perSecond = 5
$delayMs = [int](1000 / $perSecond)

Write-Host "Generating ~$perSecond TCP connections/sec to ${target}:${port}"
Write-Host "Leave this running for the whole diagnostic. Ctrl+C to stop."

$count = 0
while ($true) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        # Begin async connect, wait briefly, then close — this is enough to
        # trigger an outbound WFP connection event regardless of success.
        $iar = $c.BeginConnect($target, $port, $null, $null)
        $null = $iar.AsyncWaitHandle.WaitOne(200, $false)
        $c.Close()
    } catch {
        # Ignore connect failures — the WFP event fires on the attempt.
    }
    $count++
    if ($count % 25 -eq 0) { Write-Host "  $count connections..." }
    Start-Sleep -Milliseconds $delayMs
}
