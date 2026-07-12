"""
RedAmon Agent Logging Configuration

Configures logging with file rotation, console output, and proper formatting.
"""
import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from project_settings import get_setting

# =============================================================================
# I5 — secret redaction filter
# =============================================================================
# Scrub known token shapes from EVERY log record before any handler writes, so a
# future exception (SDK error, clone URL, header dump) carrying a secret cannot
# land in agent.log / codefix.log / triage.log in cleartext.
_REDACT_PATTERNS = [
    re.compile(r"gh[posru]_[A-Za-z0-9]{20,}"),                    # GitHub PAT / OAuth
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),                  # fine-grained PAT
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),                        # OpenAI-style keys
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),                 # Slack tokens
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),             # Bearer <token>
    re.compile(r"(?i)(authorization|api[-_]?key|x-api-key|token)\s*[:=]\s*[^\s,;]{6,}"),  # header/kv value
    re.compile(r"https?://[^/\s:@]+:[^/\s@]+@"),                  # user:pass@ in URLs (x-access-token:...@)
    re.compile(r"AKIA[0-9A-Z]{16}"),                             # AWS access key id
]
_REDACTED = "[REDACTED]"


def _redact_text(text: str) -> str:
    for pat in _REDACT_PATTERNS:
        text = pat.sub(_REDACTED, text)
    return text


class RedactingFilter(logging.Filter):
    """Rewrite token-shaped substrings in the formatted message + args to
    ``[REDACTED]``. Attached to every handler this module creates."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = _redact_text(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: _redact_text(v) if isinstance(v, str) else v
                                   for k, v in record.args.items()}
                else:
                    record.args = tuple(_redact_text(a) if isinstance(a, str) else a
                                        for a in record.args)
        except Exception:
            # Redaction must never break logging.
            pass
        return True


_REDACTING_FILTER = RedactingFilter()

# =============================================================================
# LOGGING SETTINGS
# =============================================================================

# Log directory (relative to this file)
LOG_DIR = Path(__file__).parent / "logs"

# Module-specific log directories
CODEFIX_LOG_DIR = Path(__file__).parent / "cypherfix_codefix" / "logs"
TRIAGE_LOG_DIR = Path(__file__).parent / "cypherfix_triage" / "logs"

# Module log config: (logger_name, log_dir, log_file_name)
MODULE_LOGS = [
    ("cypherfix_codefix", CODEFIX_LOG_DIR, "codefix.log"),
    ("cypherfix_triage", TRIAGE_LOG_DIR, "triage.log"),
]

# Log file settings
LOG_FILE_NAME = "agent.log"
LOG_MAX_BYTES = get_setting('LOG_MAX_MB', 10) * 1024 * 1024  # Convert MB to bytes

# Log levels
FILE_LOG_LEVEL = logging.DEBUG
CONSOLE_LOG_LEVEL = logging.INFO

# Log format
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Detailed format for file (includes more context)
FILE_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-25s | %(funcName)-20s | %(message)s"


def setup_logging(
    log_level: int = logging.INFO,
    log_to_console: bool = True,
    log_to_file: bool = True,
) -> None:
    """
    Configure logging for the RedAmon agent.

    Args:
        log_level: Minimum log level for console output
        log_to_console: Whether to output logs to console
        log_to_file: Whether to output logs to file with rotation
    """
    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Get root logger for agentic module
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture all levels, handlers will filter

    # Clear existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(_REDACTING_FILTER)  # I5
        root_logger.addHandler(console_handler)

    # File handler with rotation
    if log_to_file:
        log_file_path = LOG_DIR / LOG_FILE_NAME
        file_handler = RotatingFileHandler(
            filename=str(log_file_path),
            maxBytes=LOG_MAX_BYTES,
            backupCount=get_setting('LOG_BACKUP_COUNT', 5),
            encoding="utf-8",
        )
        file_handler.setLevel(FILE_LOG_LEVEL)
        file_formatter = logging.Formatter(FILE_LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(_REDACTING_FILTER)  # I5
        root_logger.addHandler(file_handler)

    # Module-specific file handlers (separate log files for CypherFix agents)
    if log_to_file:
        for module_name, log_dir, log_file in MODULE_LOGS:
            log_dir.mkdir(parents=True, exist_ok=True)
            module_handler = RotatingFileHandler(
                filename=str(log_dir / log_file),
                maxBytes=LOG_MAX_BYTES,
                backupCount=get_setting('LOG_BACKUP_COUNT', 5),
                encoding="utf-8",
            )
            module_handler.setLevel(FILE_LOG_LEVEL)
            module_handler.setFormatter(
                logging.Formatter(FILE_LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
            )
            module_handler.addFilter(_REDACTING_FILTER)  # I5
            module_logger = logging.getLogger(module_name)
            module_logger.handlers.clear()  # Prevent duplicates on re-init
            module_logger.addHandler(module_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)
    logging.getLogger("langchain").setLevel(logging.INFO)
    logging.getLogger("langgraph").setLevel(logging.INFO)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    # MCP client logs are very verbose - suppress them
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("mcp.client").setLevel(logging.WARNING)
    logging.getLogger("mcp.client.sse").setLevel(logging.WARNING)

    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured - File: {LOG_DIR / LOG_FILE_NAME}")
    for module_name, log_dir, log_file in MODULE_LOGS:
        logger.info(f"  Module log: {module_name} -> {log_dir / log_file}")
    logger.info(f"Max file size: {LOG_MAX_BYTES / 1024 / 1024:.1f} MB, Backup count: {get_setting('LOG_BACKUP_COUNT', 5)}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
