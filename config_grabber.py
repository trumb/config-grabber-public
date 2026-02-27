#!/usr/bin/env python3
"""
config_grabber.py - Network Switch Configuration Grabber

Connects to network switches via SSH, executes a list of commands,
and saves the output to timestamped text files.

Usage:
    python config_grabber.py -f devices.txt -c commands.txt -u admin
    python config_grabber.py -i 192.168.1.1 -c commands.txt -u admin -k ~/.ssh/id_rsa
    python config_grabber.py -i 192.168.1.1,192.168.1.2 -c commands.txt -u admin -e

Author: config-grabber
"""

import argparse          # For parsing command-line arguments
import getpass           # For securely prompting for passwords without echoing to terminal
import logging           # For structured logging output
import os                # For path and directory operations
import re                # For paging-prompt pattern matching
import sys               # For system exit on fatal errors
import time              # For delays between commands if needed
from datetime import datetime  # For generating ISO8601-formatted timestamps

import paramiko          # Third-party SSH library for Python

# keyring - cross-platform credential storage (Windows Credential Manager,
# macOS Keychain, Linux SecretService). Optional: gracefully skipped if
# not installed, with a warning when --save-credential is used.
try:
    import keyring       # pip install keyring
    _boolKeyringAvailable = True
except ImportError:
    _boolKeyringAvailable = False


# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
# Configure the root logger to write INFO-level messages to the console.
# DEBUG-level messages will be suppressed unless --verbose is passed.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Delay (in seconds) between sending each command to the switch.
# Some devices need a moment to process a command before accepting the next.
COMMAND_DELAY: float = 0.5

# Number of bytes to read at a time from the SSH channel receive buffer.
RECV_BUFFER_SIZE: int = 65535

# Maximum time (in seconds) to wait for a command's output to finish.
RECV_TIMEOUT: float = 10.0

# Compiled regex that matches common paging prompts using prefix matching.
# Prefix matching ensures variants like ---(more 38%)--- are also caught:
#   ---\(more  → ---(more)---, ---(more 38%)---, ---(more 100%)--- etc.
#   --\(?[Mm]ore → --More--, --more--, --(More)--, --(more)-- etc.
#   <---More   → <---More---> and similar variants
PAGE_PATTERN: re.Pattern = re.compile(r"---\(more|--\(?[Mm]ore|<---More")

# Module-level page-advance key (bytes for paramiko's channel.send()).
# Starts as Space; toggled to Tab if Space fails, and back if Tab stops working.
# Reset to Space at the start of each device session in run_commands_on_device().
_bytesPageKey: bytes = b" "


# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build and return the command-line argument parser.

    Returns:
        argparse.ArgumentParser: Configured parser with all supported arguments.
    """
    parser = argparse.ArgumentParser(
        prog="config_grabber",
        description=(
            "Connect to one or more network switches via SSH, run a list of "
            "commands, and save the output to timestamped .txt files.\n\n"
            "Devices may include an optional port using IP:PORT notation "
            "(e.g. 10.0.0.1:2222) for PAT/NAT environments. When no port "
            "is given, --port is used as the default."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python config_grabber.py -f devices.txt -c commands.txt -u admin\n"
            "  python config_grabber.py -i 192.168.1.1:2222 -c commands.txt -u admin -k ~/.ssh/id_rsa\n"
            "  python config_grabber.py -i 10.0.0.1:2222,10.0.0.2:2223 -c commands.txt -u admin -e\n"
        ),
    )

    # --- Target device arguments ---
    device_group = parser.add_mutually_exclusive_group(required=True)
    device_group.add_argument(
        "-i", "--ip",
        metavar="IP[,IP,...]",
        help=(
            "Single IP address or a comma-separated list of IP addresses "
            "to connect to. Mutually exclusive with --file."
        ),
    )
    device_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help=(
            "Path to a text file containing one IP address per line. "
            "Blank lines and lines starting with '#' are ignored. "
            "Mutually exclusive with --ip."
        ),
    )

    # --- Commands file ---
    parser.add_argument(
        "-c", "--commands",
        metavar="FILE",
        required=True,
        help=(
            "Path to a text file containing the commands to run on each "
            "switch, one command per line."
        ),
    )

    # --- Authentication arguments ---
    parser.add_argument(
        "-u", "--username",
        required=True,
        metavar="USER",
        help="SSH username to authenticate with.",
    )
    parser.add_argument(
        "-p", "--password",
        metavar="PASS",
        default=None,
        help=(
            "SSH password. If omitted (recommended), the script will "
            "prompt for it securely so it does not appear in shell history."
        ),
    )
    parser.add_argument(
        "-k", "--key",
        metavar="KEY_FILE",
        default=None,
        help=(
            "Path to an SSH private key file for key-based authentication. "
            "Can be used instead of, or alongside, a password."
        ),
    )
    parser.add_argument(
        "-e", "--enable",
        action="store_true",
        default=False,
        help=(
            "Send 'enable' after login to enter privileged EXEC mode. "
            "The enable password will be prompted securely."
        ),
    )

    # --- Connection tuning ---
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        metavar="PORT",
        help="SSH port to connect on (default: 22).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Connection timeout in seconds (default: 30).",
    )

    # --- Output options ---
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        default=".",
        help=(
            "Directory where output files will be saved "
            "(default: current directory)."
        ),
    )

    # --- Credential persistence ---
    parser.add_argument(
        "--save-credential",
        action="store_true",
        default=False,
        help=(
            "Save the SSH password to the OS credential store (Windows "
            "Credential Manager, macOS Keychain, or Linux SecretService) "
            "after resolving it. Requires the 'keyring' package. On next "
            "run, the saved password will be used automatically."
        ),
    )

    # --- Connection security ---
    parser.add_argument(
        "--ignore-host-key",
        action="store_true",
        default=False,
        help=(
            "Ignore SSH host key mismatches. Useful in PAT/NAT environments "
            "where multiple devices share a single public IP on different "
            "ports, each presenting a different host key. Without this flag, "
            "paramiko's AutoAddPolicy is used (accepts unknown keys but may "
            "warn on mismatches)."
        ),
    )

    # --- Paging ---
    parser.add_argument(
        "--max-page-iterations",
        type=int,
        default=100,
        metavar="N",
        help=(
            "Maximum number of paging prompts (--More-- / ---(more)---) to "
            "advance through per command before stopping. Prevents infinite "
            "loops on runaway output. Default: 100. Increase for very long "
            "command outputs (e.g. --max-page-iterations 500)."
        ),
    )

    # --- Verbosity ---
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose/debug logging.",
    )

    return parser


# ---------------------------------------------------------------------------
# Device Entry Parsing
# ---------------------------------------------------------------------------
def parse_device_entry(strEntry: str, intDefaultPort: int) -> tuple:
    """
    Parse a device entry that may include an optional port number.

    Supports the following formats:
      - ``192.168.1.1``          → uses intDefaultPort
      - ``192.168.1.1:2222``     → uses port 2222
      - ``[::1]:2222``           → IPv6 with explicit port (bracket notation)
      - ``::1``                  → bare IPv6, uses intDefaultPort

    Args:
        strEntry       (str): Raw device string from CLI or file.
        intDefaultPort (int): Port to use when none is embedded in strEntry.

    Returns:
        tuple[str, int]: A (host, port) pair ready to pass to the SSH client.
    """
    strEntry = strEntry.strip()

    # --- Handle IPv6 bracket notation: [::1]:port ---
    if strEntry.startswith("["):
        intCloseBracket = strEntry.find("]")
        if intCloseBracket == -1:
            # Malformed bracket notation - treat whole string as host
            return strEntry, intDefaultPort
        strHost = strEntry[1:intCloseBracket]  # content between [ and ]
        strRemainder = strEntry[intCloseBracket + 1:]  # everything after ]
        if strRemainder.startswith(":"):
            try:
                intPort = int(strRemainder[1:])
                return strHost, intPort
            except ValueError:
                pass  # Non-numeric port - fall through to default
        return strHost, intDefaultPort

    # --- Handle IPv4 / hostname with optional port: host:port ---
    # Count colons: exactly one colon means host:port for IPv4/hostname.
    # More than one colon means a bare IPv6 address (no port specified).
    listParts = strEntry.rsplit(":", 1)  # split on the LAST colon only
    if len(listParts) == 2:
        strPotentialHost, strPotentialPort = listParts
        # Only treat as host:port if the port portion looks like an integer
        # and the host portion is not itself a colon-containing IPv6 address.
        if strPotentialPort.isdigit() and ":" not in strPotentialHost:
            return strPotentialHost, int(strPotentialPort)

    # --- No port found - use default ---
    return strEntry, intDefaultPort


# ---------------------------------------------------------------------------
# Input File Readers
# ---------------------------------------------------------------------------
def load_ip_list(strFilePath: str, intDefaultPort: int) -> list:
    """
    Read a text file and return a list of (host, port) tuples.

    Each line may be a bare IP/hostname or an ``IP:PORT`` pair.
    Lines that are blank or start with '#' (comments) are skipped.
    Leading/trailing whitespace is stripped from each line.

    Args:
        strFilePath    (str): Path to the file containing IP addresses.
        intDefaultPort (int): SSH port to use for lines that omit a port.

    Returns:
        list[tuple[str, int]]: Non-empty list of (host, port) pairs.

    Raises:
        SystemExit: If the file cannot be opened or contains no valid entries.
    """
    listDevices = []
    try:
        with open(strFilePath, "r", encoding="utf-8") as fileHandle:
            for strLine in fileHandle:
                strLine = strLine.strip()
                # Skip blank lines and comment lines
                if not strLine or strLine.startswith("#"):
                    continue
                # Parse out the host and optional per-device port
                tupleDevice = parse_device_entry(strLine, intDefaultPort)
                listDevices.append(tupleDevice)
    except OSError as exc:
        logger.error("Cannot open IP file '%s': %s", strFilePath, exc)
        sys.exit(1)

    if not listDevices:
        logger.error("IP file '%s' contains no valid entries.", strFilePath)
        sys.exit(1)

    return listDevices


def load_command_list(strFilePath: str) -> list:
    """
    Read a text file and return a list of command strings to execute.

    Lines that are blank or start with '#' are skipped.

    Args:
        strFilePath (str): Path to the file containing commands.

    Returns:
        list[str]: Non-empty command strings.

    Raises:
        SystemExit: If the file cannot be opened or is empty.
    """
    listCommands = []
    try:
        with open(strFilePath, "r", encoding="utf-8") as fileHandle:
            for strLine in fileHandle:
                strLine = strLine.strip()
                if not strLine or strLine.startswith("#"):
                    continue
                listCommands.append(strLine)
    except OSError as exc:
        logger.error("Cannot open commands file '%s': %s", strFilePath, exc)
        sys.exit(1)

    if not listCommands:
        logger.error("Commands file '%s' contains no valid commands.", strFilePath)
        sys.exit(1)

    return listCommands


# ---------------------------------------------------------------------------
# Output File Naming
# ---------------------------------------------------------------------------
def build_output_filename(strOutputDir: str, strIP: str) -> str:
    """
    Construct the output file path using the device IP and current timestamp.

    Format: <output_dir>/<IP_address>_<YYYY-MM-DDTHHMMSS>.txt
    Colons are removed from the time portion so the name is safe on
    Windows filesystems.

    Args:
        strOutputDir (str): Directory where the file will be written.
        strIP       (str): IP address (or hostname) of the target device.

    Returns:
        str: Full absolute path to the output file.
    """
    # ISO 8601 datetime, with colons removed for Windows filename safety
    # e.g. 2026-02-26T101930  (date T time, no separators in time part)
    strTimestamp = datetime.now().strftime("%Y-%m-%dT%H%M%S")

    # Replace any characters in the IP that are illegal in filenames.
    # Colons can appear in IPv6 addresses; replace with hyphens.
    strSafeIP = strIP.replace(":", "-")

    strFileName = f"{strSafeIP}_{strTimestamp}.txt"
    return os.path.join(strOutputDir, strFileName)


# ---------------------------------------------------------------------------
# SSH Session Management
# ---------------------------------------------------------------------------
def create_ssh_client(
    strHost: str,
    intPort: int,
    strUsername: str,
    strPassword: str | None,
    strKeyFile: str | None,
    floatTimeout: float,
) -> paramiko.SSHClient:
    """
    Establish an SSH connection to a host and return the connected client.

    Tries key-based authentication first (if a key file is supplied), then
    falls back to password authentication.  The host key policy is set to
    AutoAdd so that unknown host keys are accepted automatically - suitable
    for network device management scripts on trusted networks.

    Args:
        strHost     (str)         : Hostname or IP address of the target.
        intPort     (int)         : TCP port to connect on (usually 22).
        strUsername (str)         : SSH username.
        strPassword (str | None)  : SSH password; None if using key-only auth.
        strKeyFile  (str | None)  : Path to private key file; None if using password only.
        floatTimeout (float)      : Connection timeout in seconds.

    Returns:
        paramiko.SSHClient: An authenticated, connected SSH client object.

    Raises:
        paramiko.AuthenticationException: If authentication fails.
        paramiko.SSHException            : On other SSH-level errors.
        OSError                          : On network connectivity errors.
    """
    objClient = paramiko.SSHClient()

    # Automatically accept the remote host's key.
    # NOTE: In high-security environments, replace AutoAddPolicy with
    # RejectPolicy and maintain a known_hosts file.
    objClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Build the keyword arguments for the connect() call
    dictConnectArgs = {
        "hostname": strHost,
        "port": intPort,
        "username": strUsername,
        "timeout": floatTimeout,
        "allow_agent": True,       # Allow SSH agent key forwarding
        "look_for_keys": True,     # Search ~/.ssh/ for keys automatically
    }

    # If a specific private key file was provided, load it
    if strKeyFile:
        logger.debug("Loading private key from: %s", strKeyFile)
        # RSAKey is the most common; paramiko will raise if the file type
        # does not match - catch and try other key types if needed.
        try:
            objKey = paramiko.RSAKey.from_private_key_file(strKeyFile)
        except paramiko.SSHException:
            # Try Ed25519 next (common modern key type)
            objKey = paramiko.Ed25519Key.from_private_key_file(strKeyFile)
        dictConnectArgs["pkey"] = objKey

    # Include the password if one was provided
    if strPassword:
        dictConnectArgs["password"] = strPassword

    objClient.connect(**dictConnectArgs)
    return objClient


def send_enable(objChannel: paramiko.Channel, strEnablePassword: str) -> str:
    """
    Send 'enable' to a Cisco-style shell to enter privileged EXEC mode.

    After sending 'enable', the device prompts for a password.  This
    function sends the enable password and waits for the privileged prompt
    (indicated by a '#' character at the end of the received output).

    Args:
        objChannel       (paramiko.Channel): An open interactive SSH shell channel.
        strEnablePassword (str)            : The enable/privileged password.

    Returns:
        str: The output received during the enable sequence (for logging).
    """
    # Send the 'enable' command followed by a newline.
    # paramiko's Channel.send() requires bytes, so we encode the string.
    objChannel.send(b"enable\n")
    time.sleep(COMMAND_DELAY)

    # Read whatever the device sends back (should be a password prompt)
    strResponse = receive_output(objChannel)
    logger.debug("Enable prompt response: %s", strResponse.strip())

    # Send the enable password (also encoded to bytes)
    objChannel.send((strEnablePassword + "\n").encode("utf-8"))
    time.sleep(COMMAND_DELAY)

    # Read again - should now show the privileged prompt ending with '#'
    strResponse += receive_output(objChannel)
    return strResponse


def receive_output(objChannel: paramiko.Channel) -> str:
    """
    Read all currently available output from an SSH channel.

    Polls the channel until no new data arrives for RECV_TIMEOUT seconds,
    then returns everything collected as a single string.

    Args:
        objChannel (paramiko.Channel): Active SSH shell channel to read from.

    Returns:
        str: Decoded output received from the remote device.
    """
    objChannel.settimeout(RECV_TIMEOUT)
    listChunks = []

    try:
        # Keep reading in chunks until the channel has no more data to send
        while True:
            if objChannel.recv_ready():
                bytesData = objChannel.recv(RECV_BUFFER_SIZE)
                if bytesData:
                    listChunks.append(bytesData.decode("utf-8", errors="replace"))
                else:
                    # Empty recv means the channel was closed
                    break
            else:
                # No data ready - wait briefly then check again
                # If still nothing after the timeout, we're done
                time.sleep(0.2)
                if not objChannel.recv_ready():
                    break
    except TimeoutError:
        # Timed out waiting for more output - that's normal at end of command
        pass

    return "".join(listChunks)


def read_until_complete(
    objChannel: paramiko.Channel,
    strHost: str,
    intMaxIterations: int,
) -> str:
    """
    Read all pages of output from an SSH channel, handling paging prompts.

    After an initial ``receive_output()`` call, loops while PAGE_PATTERN is
    detected in the most recent chunk of output. On each page it sends the
    current ``_bytesPageKey`` (Space by default). If Space produces no new
    output, it toggles to Tab and retries. The successful key is remembered
    in the module-level ``_bytesPageKey`` across calls within the same device
    session (reset to Space at the start of each session).

    Stops automatically when:
      - No paging prompt is found in the latest chunk, or
      - ``intMaxIterations`` pages have been advanced, or
      - Both Space and Tab fail to produce new output.

    Finally, strips all paging prompt lines from the accumulated output so
    they do not appear in the saved config file.

    Args:
        objChannel      (paramiko.Channel) : Active SSH shell channel to read from.
        strHost         (str)              : Device IP/hostname for log messages.
        intMaxIterations (int)             : Maximum page-advances before stopping.

    Returns:
        str: All accumulated output with paging prompts stripped out.
    """
    # _bytesPageKey is a module-level variable (reset per device session).
    # Using 'global' here so that toggling Space<->Tab is visible across calls.
    global _bytesPageKey

    # Read the initial chunk of output from the channel
    strChunk = receive_output(objChannel)
    strAccumulated = strChunk
    intPageCount = 0

    # Loop while the most-recently-received chunk contains a paging prompt
    while PAGE_PATTERN.search(strChunk):

        # Safety: stop if we've advanced the maximum allowed number of pages
        if intPageCount >= intMaxIterations:
            logger.warning(
                "[%s] Max page iterations (%d) reached - output may be incomplete.",
                strHost, intMaxIterations,
            )
            break
        intPageCount += 1

        # Send the current page-advance keystroke (no newline) and wait
        objChannel.send(_bytesPageKey)
        time.sleep(COMMAND_DELAY)
        strChunk = receive_output(objChannel)

        # If the current key produced no output, toggle Space<->Tab and retry
        if not strChunk:
            strOldKeyName = "Space" if _bytesPageKey == b" " else "Tab"
            _bytesPageKey = b"\t" if _bytesPageKey == b" " else b" "
            strNewKeyName = "Space" if _bytesPageKey == b" " else "Tab"
            logger.warning(
                "[%s] Paging key '%s' produced no output at page %d; switching to '%s'.",
                strHost, strOldKeyName, intPageCount, strNewKeyName,
            )

            objChannel.send(_bytesPageKey)
            time.sleep(COMMAND_DELAY)
            strChunk = receive_output(objChannel)

        # If both keys failed, abort the paging loop
        if not strChunk:
            logger.warning(
                "[%s] Both Space and Tab failed to advance pager at page %d. Stopping.",
                strHost, intPageCount,
            )
            break

        strAccumulated += strChunk

    # Strip all paging prompt lines from the final accumulated output.
    # Uses [^\r\n]* to greedily consume the rest of each prompt line so that
    # variants like ---(more 38%)--- are fully removed, not just the prefix.
    strAccumulated = re.sub(
        r"[ \t]*(?:---\(more[^\r\n]*|--\(?[Mm]ore[^\r\n]*|<---More[^\r\n]*)[ \t]*\r?\n?",
        "",
        strAccumulated,
    )

    logger.debug(
        "[%s] read_until_complete: %d page(s) advanced, %d chars total.",
        strHost, intPageCount, len(strAccumulated),
    )
    return strAccumulated


def run_commands_on_device(
    strHost: str,
    intPort: int,
    strUsername: str,
    strPassword: str | None,
    strKeyFile: str | None,
    boolEnableMode: bool,
    strEnablePassword: str | None,
    listCommands: list,
    floatTimeout: float,
    intMaxPageIterations: int = 100,
) -> str | None:
    """
    Connect to a single device, optionally enter enable mode, run all
    commands, and return the captured output as a single string.

    Args:
        strHost              (str)      : Device IP or hostname.
        intPort              (int)      : SSH port.
        strUsername          (str)      : SSH login username.
        strPassword          (str|None) : SSH password (None for key-only).
        strKeyFile           (str|None) : Private key file path.
        boolEnableMode       (bool)     : Whether to enter privileged EXEC mode.
        strEnablePassword    (str|None) : Password for enable mode.
        listCommands         (list[str]): Commands to execute sequentially.
        floatTimeout         (float)    : SSH connection timeout.
        intMaxPageIterations (int)      : Max paging prompts to advance per command.

    Returns:
        str  : Full captured output, or
        None : If the connection or authentication failed.
    """
    objClient = None
    objChannel = None

    try:
        logger.info("[%s] Connecting on port %d ...", strHost, intPort)

        # Reset the page-advance key to Space at the start of each device
        # session so every device gets a fair first attempt with Space.
        # The module-level _bytesPageKey may have been toggled to Tab by a
        # previous device that required Tab; we reset it here so the new
        # device isn't penalised for the previous device's preferences.
        global _bytesPageKey
        _bytesPageKey = b" "

        objClient = create_ssh_client(
            strHost, intPort, strUsername, strPassword, strKeyFile, floatTimeout
        )
        logger.info("[%s] Connection established.", strHost)

        # Open an interactive shell (invoke_shell) rather than exec_command
        # so that stateful commands like 'enable' work correctly.
        # exec_command opens a fresh non-interactive session per call,
        # which does not retain mode changes between commands.
        objChannel = objClient.invoke_shell()
        objChannel.settimeout(floatTimeout)

        # Allow the initial banner/prompt to arrive before sending commands
        time.sleep(1.0)
        strBanner = receive_output(objChannel)
        logger.debug("[%s] Banner/initial prompt:\n%s", strHost, strBanner)

        listOutputParts = []

        # --- Optional: Enter enable/privileged mode ---
        if boolEnableMode:
            logger.info("[%s] Entering enable mode ...", strHost)
            # strEnablePassword is guaranteed non-None here because main()
            # only sets boolEnableMode=True after prompting for the password.
            strEnableOutput = send_enable(objChannel, strEnablePassword or "")
            listOutputParts.append(strEnableOutput)
            logger.info("[%s] Enable mode active.", strHost)

        # --- Execute each command in sequence ---
        for strCmd in listCommands:
            logger.info("[%s] Running command: %s", strHost, strCmd)

            # Send the command followed by a newline.
            # paramiko's Channel.send() requires bytes - encode the string.
            objChannel.send((strCmd + "\n").encode("utf-8"))

            # Give the device time to begin processing and start sending output
            time.sleep(COMMAND_DELAY)

            # read_until_complete() handles --More-- / ---(more)--- paging
            # automatically, advancing with Space (or Tab) until all output
            # is received, then strips the paging prompts from the result.
            strCmdOutput = read_until_complete(objChannel, strHost, intMaxPageIterations)
            listOutputParts.append(strCmdOutput)

            logger.debug("[%s] Output (%d chars)", strHost, len(strCmdOutput))

        # Combine all captured output into one block
        return "".join(listOutputParts)

    except paramiko.AuthenticationException as exc:
        logger.error("[%s] Authentication failed: %s", strHost, exc)
    except paramiko.SSHException as exc:
        logger.error("[%s] SSH error: %s", strHost, exc)
    except TimeoutError:
        logger.error("[%s] Connection timed out.", strHost)
    except OSError as exc:
        logger.error("[%s] Network error: %s", strHost, exc)
    finally:
        # Always close the channel and the client, even if an exception occurred
        if objChannel:
            try:
                objChannel.close()
            except Exception:
                pass
        if objClient:
            try:
                objClient.close()
            except Exception:
                pass

    # Return None to signal that this device failed
    return None


# ---------------------------------------------------------------------------
# Output Writer
# ---------------------------------------------------------------------------
def write_output_file(strFilePath: str, strHost: str, strContent: str) -> None:
    """
    Write the captured command output to a text file.

    A small header is prepended to the file so it's clear which device
    the output came from and when it was captured.

    Args:
        strFilePath (str): Full path to the output file.
        strHost     (str): IP address or hostname of the source device.
        strContent  (str): Raw text output captured from the device.

    Raises:
        SystemExit: If the file cannot be written.
    """
    strHeader = (
        f"# Config Grabber Output\n"
        f"# Device  : {strHost}\n"
        f"# Captured: {datetime.now().isoformat()}\n"
        f"# {'=' * 60}\n\n"
    )

    try:
        with open(strFilePath, "w", encoding="utf-8") as fileHandle:
            fileHandle.write(strHeader)
            fileHandle.write(strContent)
        logger.info("[%s] Output saved to: %s", strHost, strFilePath)
    except OSError as exc:
        logger.error("[%s] Failed to write output file '%s': %s", strHost, strFilePath, exc)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
def main() -> None:
    """
    Main entry point for the config_grabber script.

    Orchestrates argument parsing, credential gathering, device iteration,
    command execution, and output file writing.
    """
    # Parse command-line arguments
    objParser = build_arg_parser()
    objArgs = objParser.parse_args()

    # Enable debug logging if the user passed --verbose
    if objArgs.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # ------------------------------------------------------------------ #
    # Resolve the list of target devices as (host, port) tuples
    # ------------------------------------------------------------------ #
    # objArgs.port is the global default; individual devices may override it
    # using IP:PORT notation.
    if objArgs.ip:
        # Parse each comma-separated entry through parse_device_entry so that
        # optional per-device ports (e.g. "10.0.0.1:2222") are respected.
        listTargetDevices = [
            parse_device_entry(strEntry.strip(), objArgs.port)
            for strEntry in objArgs.ip.split(",")
            if strEntry.strip()
        ]
    else:
        # load_ip_list also returns (host, port) tuples; pass the default port
        # so that lines without an explicit port fall back to --port.
        listTargetDevices = load_ip_list(objArgs.file, objArgs.port)

    logger.info("Loaded %d target device(s).", len(listTargetDevices))

    # ------------------------------------------------------------------ #
    # Load the list of commands to run
    # ------------------------------------------------------------------ #
    listCommands = load_command_list(objArgs.commands)
    logger.info("Loaded %d command(s) to execute.", len(listCommands))

    # ------------------------------------------------------------------ #
    # Resolve credentials (prompt for anything not provided on the CLI)
    # ------------------------------------------------------------------ #

    # Password resolution priority:
    #   1. Explicit -p / --password argument
    #   2. CONFIG_GRABBER_PASSWORD environment variable
    #   3. OS credential store via keyring (if available)
    #   4. Key-only auth (if -k is set, no password needed)
    #   5. Interactive secure prompt (last resort)
    strPassword = objArgs.password
    if strPassword is None:
        # Check environment variable
        strEnvPassword = os.environ.get("CONFIG_GRABBER_PASSWORD")
        if strEnvPassword:
            logger.info("Credential source: CONFIG_GRABBER_PASSWORD environment variable.")
            strPassword = strEnvPassword
        # Check OS credential store (keyring)
        elif _boolKeyringAvailable:
            try:
                strKeyringPassword = keyring.get_password("config-grabber", objArgs.username)
                if strKeyringPassword:
                    logger.info("Credential source: OS credential store (keyring).")
                    strPassword = strKeyringPassword
            except Exception as exc:
                logger.debug("Keyring lookup failed: %s", exc)
    if strPassword is None:
        if objArgs.key:
            # Key file provided; password is optional
            logger.info("Credential source: key-only authentication (no password).")
        else:
            # Last resort: interactive secure prompt
            logger.info("No stored credential found. Prompting for SSH password.")
            strPassword = getpass.getpass(
                prompt=f"SSH password for user '{objArgs.username}': "
            )
    elif objArgs.password is not None:
        logger.debug("Credential source: explicit --password argument.")

    # --- Save credential if --save-credential was specified ---
    if objArgs.save_credential and strPassword:
        if _boolKeyringAvailable:
            try:
                keyring.set_password("config-grabber", objArgs.username, strPassword)
                logger.info("Credential saved to OS credential store (keyring) for user '%s'.", objArgs.username)
            except Exception as exc:
                logger.warning("Failed to save credential to keyring: %s", exc)
        else:
            logger.warning("--save-credential requires the 'keyring' package: pip install keyring")

    # Enable Password: prompt if --enable was specified
    strEnablePassword = None
    if objArgs.enable:
        strEnablePassword = getpass.getpass(prompt="Enable password: ")

    # ------------------------------------------------------------------ #
    # Validate the output directory; create it if it doesn't exist
    # ------------------------------------------------------------------ #
    if not os.path.isdir(objArgs.output):
        logger.info("Creating output directory: %s", objArgs.output)
        try:
            os.makedirs(objArgs.output, exist_ok=True)
        except OSError as exc:
            logger.error("Cannot create output directory '%s': %s", objArgs.output, exc)
            sys.exit(1)

    # ------------------------------------------------------------------ #
    # Process each target device
    # ------------------------------------------------------------------ #
    intSuccess = 0  # Count of devices successfully processed
    intFailure = 0  # Count of devices that failed

    for strHost, intDevicePort in listTargetDevices:
        # intDevicePort comes from the IP:PORT entry (or the default --port
        # value when no port was specified for this particular device).
        logger.info("=" * 60)
        logger.info("Processing device: %s (port %d)", strHost, intDevicePort)

        # Run all commands on the device and collect the output.
        # intMaxPageIterations comes from --max-page-iterations (default 100).
        strOutput = run_commands_on_device(
            strHost=strHost,
            intPort=intDevicePort,                          # per-device port, not the global default
            strUsername=objArgs.username,
            strPassword=strPassword,
            strKeyFile=objArgs.key,
            boolEnableMode=objArgs.enable,
            strEnablePassword=strEnablePassword,
            listCommands=listCommands,
            floatTimeout=objArgs.timeout,
            intMaxPageIterations=objArgs.max_page_iterations,  # argparse converts - to _ in dest
        )

        if strOutput is not None:
            # Build a uniquely-named output file for this device.
            # The filename uses the host only (no port) for readability.
            strOutFile = build_output_filename(objArgs.output, strHost)
            write_output_file(strOutFile, strHost, strOutput)
            intSuccess += 1
        else:
            logger.warning("[%s] Skipped - no output captured due to errors.", strHost)
            intFailure += 1

    # ------------------------------------------------------------------ #
    # Final summary
    # ------------------------------------------------------------------ #
    logger.info("=" * 60)
    logger.info(
        "Done. %d device(s) succeeded, %d device(s) failed.",
        intSuccess,
        intFailure,
    )

    # Exit with a non-zero code if any device failed, so the script can be
    # used in automation pipelines that check return codes.
    if intFailure > 0:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Script Entry Guard
# ---------------------------------------------------------------------------
# Only run main() when this file is executed directly, not when imported
# as a module by another script.
if __name__ == "__main__":
    main()
