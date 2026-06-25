import sys
import logging
from utils import reconfigure_stdout
import config
from illumio_client import IllumioClient

# Reconfigure stdout to use utf-8 to prevent encoding issues on Windows consoles
reconfigure_stdout()

import method

# Mapping of CLI arguments to corresponding methods
AVAILABLE_METHODS = {
    "health": method.check_health,
    "labels": method.get_labels,
    "workloads": method.get_workloads,
    "vens": method.get_vens,
    "tag": method.interactive_tagging,
    "schedule": method.manage_schedule,
    "events": method.get_events,
}

def setup_logging(log_filename="illumio.log"):
    """
    Configures logging behavior.
    - All detailed logs (DEBUG/INFO/ERROR) are written to illumio.log.
    - Console logs (via the logger) are filtered to WARNING and above to prevent duplicates with standard print statements.
    """
    # 1. File Handler (captures all logs, level=DEBUG)
    file_handler = logging.FileHandler(log_filename, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    
    # 2. Console Handler (suppresses verbose log statements, level=WARNING)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # 3. Configure the Library Logger
    lib_logger = logging.getLogger("illumio_client")
    lib_logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers to avoid duplicates
    lib_logger.handlers = []
    lib_logger.addHandler(file_handler)
    lib_logger.addHandler(console_handler)

def show_help():
    """Displays the CLI help screen with available actions, parameters, and sample usages."""
    print("=" * 70)
    print(" Illumio PCE API CLI Tool - Usage Help ".center(70, "="))
    print("=" * 70)
    print("Usage: python main.py [action] [-f filter_parameter]\n")
    print("Actions & Descriptions:")
    
    commands_help = [
        {
            "name": "health",
            "desc": "Check the health status of the PCE.",
            "params": "None",
            "sample": "python main.py health"
        },
        {
            "name": "labels",
            "desc": "Retrieve security labels deployed on the PCE.",
            "params": "-f <filter_keyword> (fuzzy-matches label keys/values)",
            "sample": "python main.py labels -f app"
        },
        {
            "name": "workloads",
            "desc": "Retrieve managed/unmanaged workloads.",
            "params": "-f <filter_keyword> (fuzzy-matches name/hostname)",
            "sample": "python main.py workloads -f db"
        },
        {
            "name": "vens",
            "desc": "Retrieve VEN configurations and statuses (triggers alert email if abnormal).",
            "params": "-f <filter_keyword> (fuzzy-matches hostname/status)",
            "sample": "python main.py vens -f suspended"
        },
        {
            "name": "tag",
            "desc": "Launch interactive wizard to bulk tag workloads with security labels.",
            "params": "None",
            "sample": "python main.py tag"
        },
        {
            "name": "schedule",
            "desc": "Manage local system task scheduling (Windows task scheduler / Linux crontab).",
            "params": "None",
            "sample": "python main.py schedule"
        },
        {
            "name": "events",
            "desc": "Retrieve PCE system operation logs (default: 10 recent records).",
            "params": "-f <filter> (smart query, e.g., success, info, status=failure, max: 20 records), -notify [emails] (send results via email; if emails omitted, use default email in config)",
            "sample": "python main.py events -f \"status=failure severity=warning\" -notify \"leon_yc@syscom.com.tw, SW_Huang@syscom.com.tw\""
        },
        {
            "name": "all",
            "desc": "Run all available PCE actions sequentially.",
            "params": "-f <filter_keyword> (applies local filtering globally)",
            "sample": "python main.py all -f production"
        },
        {
            "name": "help",
            "desc": "Show this help screen detailing all available actions.",
            "params": "None",
            "sample": "python main.py help"
        }
    ]
    
    for cmd in commands_help:
        print(f"\n* Action: {cmd['name']}")
        print(f"  Description: {cmd['desc']}")
        print(f"  Parameters:  {cmd['params']}")
        print(f"  Sample:      {cmd['sample']}")
    print("\n" + "=" * 70)

def main():
    # Setup logging to illumio.log and console filter
    setup_logging()
    logger = logging.getLogger("illumio_client")
    
    # Pre-process arguments to extract -notify
    notify_emails = None
    args = sys.argv[1:]
    logger.info(f"程式啟動，原始執行參數: {args}")
    
    i = 0
    while i < len(args):
        if args[i].lower() == "-notify":
            if i + 1 < len(args) and not args[i+1].startswith("-") and args[i+1].lower() not in AVAILABLE_METHODS:
                notify_emails = args[i+1]
                args.pop(i+1)
                args.pop(i)
            else:
                notify_emails = ""  # empty string to indicate notification with default config email
                args.pop(i)
            break
        else:
            i += 1
            
    # Check for help command
    if any(h in [arg.lower() for arg in args] for h in ["help", "-h", "--help"]):
        show_help()
        sys.exit(0)
    
    # Guard clause: ensure API credentials are provided before proceeding
    if not config.API_KEY_ID or not config.API_SECRET_TOKEN or config.API_KEY_ID.startswith("api_xxxx"):
        print("[WARNING] API credentials are not fully configured.")
        print("Please check your '.env' file. Exiting.")
        sys.exit(1)
        
    # Initialize the Illumio Client
    # verify_ssl is set to False for test/dev environment convenience
    client = IllumioClient(
        pce_fqdn=config.PCE_FQDN,
        pce_port=config.PCE_PORT,
        org_id=config.ORG_ID,
        api_key_id=config.API_KEY_ID,
        api_secret_token=config.API_SECRET_TOKEN,
        verify_ssl=False
    )
    
    targets = []
    
    # Default behavior: run only health check if no args provided
    if not args:
        targets.append(("health", None))
    # Run all methods if 'all' is passed
    elif "all" in [arg.lower() for arg in args]:
        global_filter = None
        if "-f" in args:
            idx = args.index("-f")
            if idx + 1 < len(args):
                global_filter = args[idx + 1]
        for m in AVAILABLE_METHODS:
            targets.append((m, global_filter))
    # Otherwise, execute user-specified methods in sequence
    else:
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "-f":
                print("[ERROR] -f 必須接在動作後面。例如: main.py labels -f app")
                sys.exit(1)
                
            target = arg.lower()
            if target in AVAILABLE_METHODS:
                filter_val = None
                # Check if next argument is '-f'
                if i + 1 < len(args) and args[i + 1] == "-f":
                    if i + 2 < len(args):
                        filter_val = args[i + 2]
                        i += 2
                    else:
                        print("[ERROR] -f 參數後面需要提供過濾字串。")
                        sys.exit(1)
                targets.append((target, filter_val))
            else:
                print(f"[ERROR] 未知動作: {arg}")
                print(f"可用動作: {', '.join(AVAILABLE_METHODS.keys())} 或 all")
                sys.exit(1)
            i += 1
                
    # Execute actions sequentially
    for target, filter_val in targets:
        func = AVAILABLE_METHODS[target]
        logger.info(f"開始執行動作: {target}" + (f" (過濾條件: '{filter_val}')" if filter_val else ""))
        if target == "events":
            func(client, filter_val, notify_emails=notify_emails)
        else:
            func(client, filter_val)

if __name__ == "__main__":
    main()
