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
import sys               # For system exit on fatal errors
import time              # For delays between commands if needed
from datetime import datetime  # For generating ISO8601-formatted timestamps

import paramiko          # Third-party SSH library for Python


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
            "commands, and save the output to timestamped .txt files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python config_grabber.py -f devices.txt -c commands.txt -u admin\n"
            "  python config_grabber.py -i 192.168.1.1 -c commands.txt -u admin -k ~/.ssh/id_rsa\n"
            "  python config_grabber.py -i 192.168.1.1,10.0.0.1 -c commands.txt -u admin -e\n"
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

    # --- Verbosity ---
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose/debug logging.",
    )

    return parser


# ---------------------------------------------------------------------------
# Input File Readers
# ---------------------------------------------------------------------------
def load_ip_list(strFilePath: str) -> list:
    """
    Read a text file and return a list of IP address strings.

    Lines that are blank or start with '#' (comments) are skipped.
    Leading/trailing whitespace is stripped from each line.

    Args:
        strFilePath (str): Path to the file containing IP addresses.

    Returns:
        list[str]: Non-empty, stripped IP address strings.

    Raises:
        SystemExit: If the file cannot be opened.
    """
    listIPs = []
    try:
        with open(strFilePath, "r", encoding="utf-8") as fileHandle:
            for strLine in fileHandle:
                strLine = strLine.strip()
                # Skip blank lines and comment lines
                if not strLine or strLine.startswith("#"):
                    continue
                listIPs.append(strLine)
    except OSError as exc:
        logger.error("Cannot open IP file '%s': %s", strFilePath, exc)
        sys.exit(1)

    if not listIPs:
        logger.error("IP file '%s' contains no valid entries.", strFilePath)
        sys.exit(1)

    return listIPs


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
    # Send the 'enable' command followed by a newline
    objChannel.send("enable\n")
    time.sleep(COMMAND_DELAY)

    # Read whatever the device sends back (should be a password prompt)
    strResponse = receive_output(objChannel)
    logger.debug("Enable prompt response: %s", strResponse.strip())

    # Send the enable password
    objChannel.send(strEnablePassword + "\n")
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
) -> str | None:
    """
    Connect to a single device, optionally enter enable mode, run all
    commands, and return the captured output as a single string.

    Args:
        strHost           (str)        : Device IP or hostname.
        intPort           (int)        : SSH port.
        strUsername       (str)        : SSH login username.
        strPassword       (str|None)   : SSH password (None for key-only).
        strKeyFile        (str|None)   : Private key file path.
        boolEnableMode    (bool)       : Whether to enter privileged EXEC mode.
        strEnablePassword (str|None)   : Password for enable mode.
        listCommands      (list[str])  : Commands to execute sequentially.
        floatTimeout      (float)      : SSH connection timeout.

    Returns:
        str  : Full captured output, or
        None : If the connection or authentication failed.
    """
    objClient = None
    objChannel = None

    try:
        logger.info("[%s] Connecting on port %d ...", strHost, intPort)
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
            strEnableOutput = send_enable(objChannel, strEnablePassword)
            listOutputParts.append(strEnableOutput)
            logger.info("[%s] Enable mode active.", strHost)

        # --- Execute each command in sequence ---
        for strCmd in listCommands:
            logger.info("[%s] Running command: %s", strHost, strCmd)

            # Send the command followed by a newline (carriage return)
            objChannel.send(strCmd + "\n")

            # Give the device time to process and respond
            time.sleep(COMMAND_DELAY)

            # Read the output for this command
            strCmdOutput = receive_output(objChannel)
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
    # Resolve the list of target IP addresses
    # ------------------------------------------------------------------ #
    if objArgs.ip:
        # Split a comma-separated list and strip whitespace from each entry
        listTargetIPs = [strIP.strip() for strIP in objArgs.ip.split(",") if strIP.strip()]
    else:
        # Read IPs from the specified file
        listTargetIPs = load_ip_list(objArgs.file)

    logger.info("Loaded %d target device(s).", len(listTargetIPs))

    # ------------------------------------------------------------------ #
    # Load the list of commands to run
    # ------------------------------------------------------------------ #
    listCommands = load_command_list(objArgs.commands)
    logger.info("Loaded %d command(s) to execute.", len(listCommands))

    # ------------------------------------------------------------------ #
    # Resolve credentials (prompt for anything not provided on the CLI)
    # ------------------------------------------------------------------ #

    # SSH Password: prompt securely if not supplied via -p
    strPassword = objArgs.password
    if strPassword is None and objArgs.key is None:
        # Neither a password nor a key was provided - must prompt for password
        strPassword = getpass.getpass(
            prompt=f"SSH password for user '{objArgs.username}': "
        )
    elif strPassword is None and objArgs.key:
        # A key file was given; password is optional (may still be needed
        # if the key itself is passphrase-protected - paramiko handles that
        # interactively).  Only ask if the user also wants password auth.
        pass  # key-only authentication; no password required

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

    for strIP in listTargetIPs:
        logger.info("=" * 60)
        logger.info("Processing device: %s", strIP)

        # Run all commands on the device and collect the output
        strOutput = run_commands_on_device(
            strHost=strIP,
            intPort=objArgs.port,
            strUsername=objArgs.username,
            strPassword=strPassword,
            strKeyFile=objArgs.key,
            boolEnableMode=objArgs.enable,
            strEnablePassword=strEnablePassword,
            listCommands=listCommands,
            floatTimeout=objArgs.timeout,
        )

        if strOutput is not None:
            # Build a uniquely-named output file for this device
            strOutFile = build_output_filename(objArgs.output, strIP)
            write_output_file(strOutFile, strIP, strOutput)
            intSuccess += 1
        else:
            logger.warning("[%s] Skipped - no output captured due to errors.", strIP)
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
