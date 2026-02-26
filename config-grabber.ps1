#Requires -Modules Posh-SSH
<#
.SYNOPSIS
    Network Switch Configuration Grabber (PowerShell / Posh-SSH edition).

.DESCRIPTION
    Connects to one or more network switches via SSH using the Posh-SSH module,
    executes a list of commands read from a text file, and saves the output to
    a timestamped .txt file for each device.

    Devices may be specified as bare IP addresses or as IP:PORT pairs to support
    PAT/NAT environments where multiple devices share a single public IP but use
    different TCP ports.

    Authentication supports both password (prompted securely) and SSH private keys.
    Cisco-style privileged EXEC (enable) mode is also supported.

    Requires the Posh-SSH module:
        Install-Module -Name Posh-SSH -Scope CurrentUser

.PARAMETER IP
    One or more IP addresses (or hostnames) as a comma-separated string.
    Each entry may optionally include a port using IP:PORT notation.
    Mutually exclusive with -DeviceFile.

.PARAMETER DeviceFile
    Path to a text file containing one device per line (IP or IP:PORT).
    Lines starting with '#' and blank lines are ignored.
    Mutually exclusive with -IP.

.PARAMETER CommandFile
    Required. Path to a text file containing the commands to run on each
    switch, one command per line. Lines starting with '#' are ignored.

.PARAMETER Username
    Required. SSH login username.

.PARAMETER Password
    SSH password as a SecureString. If omitted, the script will prompt
    securely so the password does not appear in shell history.

.PARAMETER KeyFile
    Path to an SSH private key file for key-based authentication.
    Can be used instead of, or alongside, a password.

.PARAMETER Enable
    If specified, sends the 'enable' command after login to enter Cisco
    privileged EXEC mode. The enable password is prompted securely.

.PARAMETER Port
    Default SSH port to use when a device entry does not include a port.
    Defaults to 22.

.PARAMETER Timeout
    SSH connection timeout in seconds. Defaults to 30.

.PARAMETER MaxPageIterations
    Maximum number of paging prompts (--More-- / ---(more)---) to advance
    through per command before stopping. Prevents infinite loops on runaway
    output. Defaults to 100. Override with a higher value for very long
    command outputs (e.g. -MaxPageIterations 500).

.PARAMETER OutputDir
    Directory where output .txt files will be saved.
    Created automatically if it does not exist. Defaults to the current directory.

.EXAMPLE
    # Single switch - prompted for password
    .\config-grabber.ps1 -IP 192.168.1.1 -CommandFile commands.txt -Username admin

.EXAMPLE
    # Device file, SSH key, save to .\output
    .\config-grabber.ps1 -DeviceFile devices.txt -CommandFile commands.txt `
        -Username admin -KeyFile ~/.ssh/id_rsa -OutputDir .\output

.EXAMPLE
    # PAT environment - per-device ports
    .\config-grabber.ps1 -IP "203.0.113.1:2221,203.0.113.1:2222" `
        -CommandFile commands.txt -Username admin -OutputDir .\output

.EXAMPLE
    # Enable mode
    .\config-grabber.ps1 -DeviceFile devices.txt -CommandFile commands.txt `
        -Username admin -Enable -OutputDir .\output
#>

[CmdletBinding(DefaultParameterSetName = 'ByIP')]
param (
    # --- Target device arguments (mutually exclusive) ---
    [Parameter(Mandatory, ParameterSetName = 'ByIP')]
    [string]$IP,

    [Parameter(Mandatory, ParameterSetName = 'ByFile')]
    [string]$DeviceFile,

    # --- Required arguments ---
    [Parameter(Mandatory)]
    [string]$CommandFile,

    [Parameter(Mandatory)]
    [string]$Username,

    # --- Authentication ---
    [Parameter()]
    [SecureString]$Password,

    [Parameter()]
    [string]$KeyFile,

    [Parameter()]
    [switch]$Enable,

    # --- Connection tuning ---
    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$Port = 22,

    [Parameter()]
    [int]$Timeout = 30,

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$MaxPageIterations = 100,

    # --- Connection security ---
    [Parameter()]
    [switch]$IgnoreHostKeyMismatch,

    # --- Output ---
    [Parameter()]
    [string]$OutputDir = '.'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Delay in milliseconds between writing a command and reading its output.
[int]$script:intCommandDelayMs = 500

# Delay in milliseconds to wait for the initial SSH banner to arrive.
[int]$script:intBannerDelayMs  = 1000

# Regex pattern that matches common "press key to continue" paging prompts.
# Uses prefix matching so variants like ---(more 38%)--- are also caught:
#   ---\(more  matches ---(more)---, ---(more 38%)---, ---(more 100%)--- etc.
#   --\(?[Mm]ore  matches --More--, --more--, --(More)--, --(more)-- etc.
#   <---More   matches <---More---> and similar variants
[string]$script:strPagePattern = '---\(more|--\(?[Mm]ore|<---More'

# Keystroke used to advance past a paging prompt.
# Starts as Space (most common); automatically toggled to Tab if Space fails.
# Reset to Space at the start of each device session.
[string]$script:strPageKey = ' '

# ---------------------------------------------------------------------------
# Helper: Write a timestamped log message to the console.
# Uses Write-Verbose for debug info (visible with -Verbose switch).
# ---------------------------------------------------------------------------
function Write-Log {
    <#
    .SYNOPSIS
        Write a formatted INFO message to the host.
    .PARAMETER strMessage
        The message string to display.
    #>
    param ([string]$strMessage)
    $strTimestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    Write-Host "$strTimestamp  INFO     $strMessage"
}

function Write-LogWarning {
    param ([string]$strMessage)
    $strTimestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    Write-Warning "$strTimestamp  WARNING  $strMessage"
}

function Write-LogError {
    param ([string]$strMessage)
    $strTimestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    Write-Host "$strTimestamp  ERROR    $strMessage" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# Helper: Parse a device entry that may include IP:PORT notation.
# Supports IPv4, hostnames, and IPv6 [::1]:port bracket notation.
# Returns a hashtable with keys 'Host' and 'Port'.
# ---------------------------------------------------------------------------
function Resolve-DeviceEntry {
    <#
    .SYNOPSIS
        Parse a device string into a host/port pair.
    .PARAMETER strEntry
        Raw entry such as '192.168.1.1', '10.0.0.1:2222', or '[::1]:2222'.
    .PARAMETER intDefaultPort
        Port to use when no port is embedded in the entry.
    .OUTPUTS
        Hashtable with 'Host' (string) and 'Port' (int).
    #>
    param (
        [string]$strEntry,
        [int]$intDefaultPort
    )

    $strEntry = $strEntry.Trim()

    # --- IPv6 bracket notation: [::1]:port ---
    if ($strEntry.StartsWith('[')) {
        $intClose = $strEntry.IndexOf(']')
        if ($intClose -ge 0) {
            $strHost      = $strEntry.Substring(1, $intClose - 1)   # between [ and ]
            $strRemainder = $strEntry.Substring($intClose + 1)       # after ]
            if ($strRemainder.StartsWith(':')) {
                $strPortPart = $strRemainder.Substring(1)
                if ($strPortPart -match '^\d+$') {
                    return @{ Host = $strHost; Port = [int]$strPortPart }
                }
            }
            return @{ Host = $strHost; Port = $intDefaultPort }
        }
    }

    # --- IPv4 / hostname with optional port: split on the LAST colon ---
    # Only treat as host:port when there is exactly one colon (IPv4/hostname).
    # A bare IPv6 address has multiple colons - leave it untouched.
    $intLastColon = $strEntry.LastIndexOf(':')
    if ($intLastColon -gt 0) {
        $strPotentialHost = $strEntry.Substring(0, $intLastColon)
        $strPotentialPort = $strEntry.Substring($intLastColon + 1)
        # Only treat as port if the potential port is a number and the host
        # portion itself contains no colon (which would indicate bare IPv6).
        if ($strPotentialPort -match '^\d+$' -and $strPotentialHost -notmatch ':') {
            return @{ Host = $strPotentialHost; Port = [int]$strPotentialPort }
        }
    }

    # --- No port found: use the default ---
    return @{ Host = $strEntry; Port = $intDefaultPort }
}

# ---------------------------------------------------------------------------
# Helper: Load a list of devices from a text file.
# Returns an array of hashtables with 'Host' and 'Port' keys.
# ---------------------------------------------------------------------------
function Get-DeviceList {
    <#
    .SYNOPSIS
        Read a device file and return a list of host/port pairs.
    .PARAMETER strFilePath
        Path to the file containing IP addresses (one per line).
    .PARAMETER intDefaultPort
        Port to use for lines that omit a port.
    #>
    param (
        [string]$strFilePath,
        [int]$intDefaultPort
    )

    if (-not (Test-Path $strFilePath)) {
        Write-LogError "Device file not found: $strFilePath"
        exit 1
    }

    $listDevices = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($strLine in Get-Content $strFilePath) {
        $strLine = $strLine.Trim()
        # Skip blank lines and comment lines (starting with '#')
        if ([string]::IsNullOrWhiteSpace($strLine) -or $strLine.StartsWith('#')) { continue }
        $listDevices.Add((Resolve-DeviceEntry -strEntry $strLine -intDefaultPort $intDefaultPort))
    }

    if ($listDevices.Count -eq 0) {
        Write-LogError "Device file '$strFilePath' contains no valid entries."
        exit 1
    }

    return $listDevices
}

# ---------------------------------------------------------------------------
# Helper: Load commands from a text file. Returns a string array.
# ---------------------------------------------------------------------------
function Get-CommandList {
    <#
    .SYNOPSIS
        Read a commands file and return an array of command strings.
    .PARAMETER strFilePath
        Path to the file containing commands (one per line).
    #>
    param ([string]$strFilePath)

    if (-not (Test-Path $strFilePath)) {
        Write-LogError "Commands file not found: $strFilePath"
        exit 1
    }

    $listCommands = [System.Collections.Generic.List[string]]::new()

    foreach ($strLine in Get-Content $strFilePath) {
        $strLine = $strLine.Trim()
        if ([string]::IsNullOrWhiteSpace($strLine) -or $strLine.StartsWith('#')) { continue }
        $listCommands.Add($strLine)
    }

    if ($listCommands.Count -eq 0) {
        Write-LogError "Commands file '$strFilePath' contains no valid commands."
        exit 1
    }

    # The comma operator (,) prevents PowerShell from unwrapping a single-element
    # collection to a scalar string, which would cause .Count to fail under
    # Set-StrictMode -Version Latest. ToArray() converts the Generic.List to a
    # plain string[] array that Invoke-DeviceCommands expects.
    return ,$listCommands.ToArray()
}

# ---------------------------------------------------------------------------
# Helper: Build the output file path from device IP and current timestamp.
# ---------------------------------------------------------------------------
function Get-OutputFilePath {
    <#
    .SYNOPSIS
        Build a timestamped output file path for a given device.
    .PARAMETER strOutputDir
        Directory where the file will be written.
    .PARAMETER strHost
        IP address or hostname of the target device.
    .OUTPUTS
        String: Full file path.
    #>
    param (
        [string]$strOutputDir,
        [string]$strHost
    )

    # ISO 8601-like timestamp: YYYY-MM-DDTHHMMSS (no colons in time for Windows safety)
    $strTimestamp = (Get-Date).ToString('yyyy-MM-ddTHHmmss')

    # Replace colons in IPv6 addresses with hyphens for filename safety
    $strSafeHost  = $strHost -replace ':', '-'

    return Join-Path $strOutputDir "${strSafeHost}_${strTimestamp}.txt"
}

# ---------------------------------------------------------------------------
# Helper: Write the output file with a metadata header.
# ---------------------------------------------------------------------------
function Save-OutputFile {
    <#
    .SYNOPSIS
        Write captured device output to a timestamped text file.
    .PARAMETER strFilePath
        Full path of the file to create.
    .PARAMETER strHost
        IP or hostname of the device (used in the header).
    .PARAMETER strContent
        Raw output text captured from the device.
    #>
    param (
        [string]$strFilePath,
        [string]$strHost,
        [string]$strContent
    )

    $strHeader = @"
# Config Grabber Output (PowerShell)
# Device  : $strHost
# Captured: $((Get-Date).ToString('o'))
# $('=' * 60)

"@

    try {
        $strHeader + $strContent | Set-Content -Path $strFilePath -Encoding UTF8
        Write-Log "[$strHost] Output saved to: $strFilePath"
    }
    catch {
        Write-LogError "[$strHost] Failed to write output file '$strFilePath': $_"
    }
}

# ---------------------------------------------------------------------------
# Helper: Read all pages of output from an SSH shell stream.
# Handles paging prompts like --More-- and ---(more)--- by sending Space
# (or Tab) keystrokes to advance. Toggles Space<->Tab when one fails.
# The successful key is remembered in $script:strPageKey for the session.
# ---------------------------------------------------------------------------
function Read-StreamUntilComplete {
    <#
    .SYNOPSIS
        Read all pages of output from an SSH shell stream.
    .DESCRIPTION
        Performs an initial Read(), then loops while a paging prompt is
        detected in the latest chunk of output. On each page it sends the
        current $script:strPageKey (Space by default). If Space produces
        no new output, it toggles to Tab and retries. The working key is
        remembered across calls within the same device session.
        Stops when no paging prompt is found or MaxIterations is reached.
    .PARAMETER objStream
        The Posh-SSH SSHShellStream to read from.
    .PARAMETER strHost
        Device hostname/IP used in log messages.
    .PARAMETER intDelayMs
        Milliseconds to wait after each keystroke before reading again.
    .PARAMETER intMaxIterations
        Maximum number of page-advances before stopping (safety limit).
    .OUTPUTS
        String containing all accumulated output with paging prompts removed.
    #>
    param (
        [object]$objStream,
        [string]$strHost,
        [int]$intDelayMs,
        [int]$intMaxIterations
    )

    # Read the initial chunk of output from the stream
    $strChunk       = $objStream.Read()
    $strAccumulated = $strChunk
    [int]$intPageCount = 0

    # Loop while the most recent chunk contains a paging prompt
    while ($strChunk -match $script:strPagePattern) {

        # Safety: stop if we've exceeded the maximum number of pages
        if ($intPageCount -ge $intMaxIterations) {
            Write-LogWarning "[$strHost] Max page iterations ($intMaxIterations) reached - output may be incomplete."
            break
        }
        $intPageCount++

        # Send the current page-advance keystroke (no newline) and wait
        $objStream.Write($script:strPageKey)
        Start-Sleep -Milliseconds $intDelayMs
        $strChunk = $objStream.Read()

        # If the current key produced no new output, toggle Space<->Tab and retry
        if ([string]::IsNullOrEmpty($strChunk)) {
            $strOldKeyName     = if ($script:strPageKey -eq ' ') { 'Space' } else { 'Tab' }
            $script:strPageKey = if ($script:strPageKey -eq ' ') { "`t"   } else { ' '  }
            $strNewKeyName     = if ($script:strPageKey -eq ' ') { 'Space' } else { 'Tab' }
            Write-LogWarning "[$strHost] Paging key '$strOldKeyName' produced no output at page $intPageCount; switching to '$strNewKeyName'."

            $objStream.Write($script:strPageKey)
            Start-Sleep -Milliseconds $intDelayMs
            $strChunk = $objStream.Read()
        }

        # If both keys failed, abort the paging loop
        if ([string]::IsNullOrEmpty($strChunk)) {
            Write-LogWarning "[$strHost] Both Space and Tab failed to advance pager at page $intPageCount. Stopping."
            break
        }

        $strAccumulated += $strChunk
    }

    # Strip all paging prompt lines from the final output so they don't
    # appear in the saved config file.
    # Uses [^\r\n]* to greedily consume the rest of the prompt line so that
    # variants like ---(more 38%)--- are fully removed, not just the prefix.
    $strAccumulated = $strAccumulated -replace '(?m)[ \t]*(?:---\(more[^\r\n]*|--\(?[Mm]ore[^\r\n]*|<---More[^\r\n]*)[ \t]*\r?\n?', ''

    Write-Verbose "[$strHost] Read-StreamUntilComplete: $intPageCount page(s) advanced, $($strAccumulated.Length) chars total."
    return $strAccumulated
}

# ---------------------------------------------------------------------------
# Core: Connect to a single device and run all commands.
# Returns the captured output as a string, or $null on failure.
# ---------------------------------------------------------------------------
function Invoke-DeviceCommands {
    <#
    .SYNOPSIS
        SSH into a device, optionally enter enable mode, run all commands,
        and return the combined output as a string.
    .PARAMETER strHost
        Device hostname or IP address.
    .PARAMETER intDevicePort
        SSH port for this specific device.
    .PARAMETER strUsername
        SSH login username.
    .PARAMETER objCredential
        PSCredential object containing the SSH password (or dummy for key-only auth).
    .PARAMETER strKeyFile
        Path to SSH private key file. Pass $null to skip key auth.
    .PARAMETER boolEnableMode
        Whether to send 'enable' after login.
    .PARAMETER secEnablePassword
        SecureString containing the enable password. Pass $null if not needed.
    .PARAMETER listCommands
        Array of command strings to execute.
    .PARAMETER intTimeout
        SSH connection timeout in seconds.
    .OUTPUTS
        String containing all captured output, or $null on failure.
    #>
    param (
        [string]$strHost,
        [int]$intDevicePort,
        [System.Management.Automation.PSCredential]$objCredential,
        [string]$strKeyFile,
        [bool]$boolEnableMode,
        [SecureString]$secEnablePassword,
        [string[]]$listCommands,
        [int]$intTimeout,
        [int]$intMaxPageIterations,
        [bool]$boolIgnoreHostKeyMismatch
    )

    $objSession = $null
    $objStream  = $null

    try {
        Write-Log "[$strHost] Connecting on port $intDevicePort ..."

        # Reset the page-advance key to Space at the start of each device
        # session so each device gets a fair first attempt with Space.
        $script:strPageKey = ' '

        # --- Clear cached SSH host keys when -IgnoreHostKeyMismatch is set ---
        # In PAT/NAT environments, the same public IP maps to different internal
        # devices via different ports. Each device has its own SSH host key but
        # Posh-SSH caches keys per IP (ignoring port), so a second device on the
        # same IP causes a mismatch. AcceptKey=$true only handles *unknown* keys,
        # not *mismatched* ones. When IgnoreHostKeyMismatch is enabled we
        # aggressively remove ALL cached keys for this IP before connecting so
        # that AcceptKey=$true can accept each device's key fresh.
        if ($boolIgnoreHostKeyMismatch) {
            try {
                # Remove every cached entry for this IP, regardless of key type.
                # ForEach-Object handles the case where multiple key types are stored.
                Get-SSHTrustedHost | Where-Object { $_.SSHHost -eq $strHost } | ForEach-Object {
                    Remove-SSHTrustedHost -SSHHost $strHost -ErrorAction SilentlyContinue | Out-Null
                }
                Write-Verbose "[$strHost] Cleared all cached SSH host keys (-IgnoreHostKeyMismatch)."
            }
            catch {
                Write-Verbose "[$strHost] No cached SSH host key to remove (or removal failed - continuing)."
            }
        }

        # Build the connection parameter hashtable dynamically
        # so we can conditionally add -KeyFile without branching the call.
        $dictConnectParams = @{
            ComputerName      = $strHost
            Port              = $intDevicePort
            Credential        = $objCredential
            ConnectionTimeout = $intTimeout
            AcceptKey         = $true        # Auto-accept unknown host keys (equiv. to AutoAddPolicy)
            ErrorAction       = 'Stop'
        }

        # Add the key file if one was specified
        if (-not [string]::IsNullOrWhiteSpace($strKeyFile)) {
            Write-Verbose "[$strHost] Using key file: $strKeyFile"
            $dictConnectParams['KeyFile'] = $strKeyFile
        }

        # Establish the SSH session via Posh-SSH
        $objSession = New-SSHSession @dictConnectParams
        Write-Log "[$strHost] Connection established (session ID: $($objSession.SessionId))."

        # Open an interactive shell stream.
        # We use a shell stream rather than Invoke-SSHCommand so that
        # stateful commands like 'enable' persist across invocations.
        $objStream = New-SSHShellStream -SessionId $objSession.SessionId

        # Wait for the initial banner / prompt to arrive
        Start-Sleep -Milliseconds $script:intBannerDelayMs
        $strBanner = $objStream.Read()
        Write-Verbose "[$strHost] Banner/initial prompt:`n$strBanner"

        $listOutputParts = [System.Collections.Generic.List[string]]::new()

        # --- Optional: Enter Cisco-style privileged EXEC (enable) mode ---
        if ($boolEnableMode) {
            Write-Log "[$strHost] Entering enable mode ..."

            # Send the 'enable' command
            $objStream.WriteLine('enable')
            Start-Sleep -Milliseconds $script:intCommandDelayMs

            # Read the password prompt the device sends back
            $strEnablePrompt = $objStream.Read()
            Write-Verbose "[$strHost] Enable prompt: $strEnablePrompt"
            $listOutputParts.Add($strEnablePrompt)

            # Convert the SecureString enable password back to plain text
            # to send it over the SSH channel, then immediately discard it.
            $objBSTR          = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secEnablePassword)
            $strEnablePlain   = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($objBSTR)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($objBSTR)   # zero memory immediately

            $objStream.WriteLine($strEnablePlain)
            $strEnablePlain = $null   # release reference
            Start-Sleep -Milliseconds $script:intCommandDelayMs

            # Use Read-StreamUntilComplete in case the enable response is paged
            $strEnableResponse = Read-StreamUntilComplete `
                -objStream       $objStream `
                -strHost         $strHost `
                -intDelayMs      $script:intCommandDelayMs `
                -intMaxIterations $intMaxPageIterations
            $listOutputParts.Add($strEnableResponse)
            Write-Log "[$strHost] Enable mode active."
        }

        # --- Execute each command in sequence ---
        foreach ($strCmd in $listCommands) {
            Write-Log "[$strHost] Running: $strCmd"

            $objStream.WriteLine($strCmd)
            Start-Sleep -Milliseconds $script:intCommandDelayMs

            # Read-StreamUntilComplete handles --More-- / ---(more)--- paging
            # automatically, advancing with Space (or Tab) until all output
            # is received, then strips the paging prompts from the result.
            $strCmdOutput = Read-StreamUntilComplete `
                -objStream       $objStream `
                -strHost         $strHost `
                -intDelayMs      $script:intCommandDelayMs `
                -intMaxIterations $intMaxPageIterations
            $listOutputParts.Add($strCmdOutput)

            Write-Verbose "[$strHost] Output length: $($strCmdOutput.Length) chars"
        }

        # Return all captured output as a single string
        return ($listOutputParts -join '')

    }
    catch {
        Write-LogError "[$strHost] Error: $_"
        return $null
    }
    finally {
        # Always clean up the SSH session, even on error
        if ($null -ne $objSession) {
            try { Remove-SSHSession -SessionId $objSession.SessionId | Out-Null }
            catch {}
        }
    }
}

# ===========================================================================
# MAIN
# ===========================================================================

Write-Log 'Config Grabber (PowerShell / Posh-SSH) starting...'

# ---------------------------------------------------------------------------
# Check Posh-SSH is available
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
    Write-LogError "Posh-SSH module is not installed. Run: Install-Module -Name Posh-SSH -Scope CurrentUser"
    exit 1
}
Import-Module Posh-SSH -ErrorAction Stop

# ---------------------------------------------------------------------------
# Resolve device list as array of @{ Host; Port } hashtables
# ---------------------------------------------------------------------------
$listTargetDevices = [System.Collections.Generic.List[hashtable]]::new()

if ($PSCmdlet.ParameterSetName -eq 'ByIP') {
    # Split comma-separated list and parse each entry for optional :PORT
    foreach ($strEntry in ($IP -split ',')) {
        $strEntry = $strEntry.Trim()
        if (-not [string]::IsNullOrWhiteSpace($strEntry)) {
            $listTargetDevices.Add((Resolve-DeviceEntry -strEntry $strEntry -intDefaultPort $Port))
        }
    }
}
else {
    # Load from file
    $listTargetDevices.AddRange((Get-DeviceList -strFilePath $DeviceFile -intDefaultPort $Port))
}

Write-Log "Loaded $($listTargetDevices.Count) target device(s)."

# ---------------------------------------------------------------------------
# Load commands
# ---------------------------------------------------------------------------
$arrCommands = Get-CommandList -strFilePath $CommandFile
Write-Log "Loaded $($arrCommands.Count) command(s) to execute."

# ---------------------------------------------------------------------------
# Resolve credentials
# ---------------------------------------------------------------------------

# Password resolution priority:
#   1. Explicit -Password argument (already in $Password if supplied)
#   2. CONFIG_GRABBER_PASSWORD environment variable
#   3. Key-only auth (if -KeyFile is set, no password needed)
#   4. Interactive secure prompt (last resort)
if ($null -eq $Password) {
    # Check environment variable first
    $strEnvPassword = $env:CONFIG_GRABBER_PASSWORD
    if (-not [string]::IsNullOrWhiteSpace($strEnvPassword)) {
        Write-Log 'Credential source: CONFIG_GRABBER_PASSWORD environment variable.'
        $Password = ConvertTo-SecureString -String $strEnvPassword -AsPlainText -Force
        $strEnvPassword = $null   # clear plain text reference
    }
    elseif (-not [string]::IsNullOrWhiteSpace($KeyFile)) {
        # Key file was given; create a dummy empty-password credential for Posh-SSH.
        # Posh-SSH requires a PSCredential even for key auth.
        Write-Log 'Credential source: key-only authentication (no password).'
        $Password = New-Object SecureString
    }
    else {
        # Neither password, env var, nor key provided - must prompt
        Write-Log 'No stored credential found. Prompting for SSH password.'
        $Password = Read-Host -Prompt "SSH password for user '$Username'" -AsSecureString
    }
}
else {
    Write-Verbose 'Credential source: explicit -Password argument.'
}

# Build the PSCredential object required by New-SSHSession
$objCredential = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Enable password: prompt if -Enable was specified
$secEnablePassword = $null
if ($Enable) {
    $secEnablePassword = Read-Host -Prompt 'Enable password' -AsSecureString
}

# ---------------------------------------------------------------------------
# Validate / create the output directory
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputDir)) {
    Write-Log "Creating output directory: $OutputDir"
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ---------------------------------------------------------------------------
# Process each device
# ---------------------------------------------------------------------------
$intSuccess = 0
$intFailure = 0

foreach ($dictDevice in $listTargetDevices) {
    $strHost       = $dictDevice.Host
    $intDevicePort = $dictDevice.Port

    Write-Log ('=' * 60)
    Write-Log "Processing device: $strHost (port $intDevicePort)"

    $strOutput = Invoke-DeviceCommands `
        -strHost                  $strHost `
        -intDevicePort            $intDevicePort `
        -objCredential            $objCredential `
        -strKeyFile               $KeyFile `
        -boolEnableMode           ($Enable.IsPresent) `
        -secEnablePassword        $secEnablePassword `
        -listCommands             $arrCommands `
        -intTimeout               $Timeout `
        -intMaxPageIterations     $MaxPageIterations `
        -boolIgnoreHostKeyMismatch ($IgnoreHostKeyMismatch.IsPresent)

    if ($null -ne $strOutput) {
        $strOutFile = Get-OutputFilePath -strOutputDir $OutputDir -strHost $strHost
        Save-OutputFile -strFilePath $strOutFile -strHost $strHost -strContent $strOutput
        $intSuccess++
    }
    else {
        Write-LogWarning "[$strHost] Skipped - no output captured due to errors."
        $intFailure++
    }
}

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
Write-Log ('=' * 60)
Write-Log "Done. $intSuccess device(s) succeeded, $intFailure device(s) failed."

# Exit with code 1 if any device failed (allows use in automation pipelines)
if ($intFailure -gt 0) { exit 1 }
