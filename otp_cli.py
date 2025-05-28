import base64
from urllib.parse import unquote, urlparse, parse_qs, urlencode, urlunparse, quote
import io
import struct
import pyotp
import time
import json
import os
import sys
import argparse

# --- ANSI Color Codes ---
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_CYAN = "\033[96m"
COLOR_RED = "\033[91m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"

# --- Protobuf Parsing Logic (for otpauth-migration) ---

def varint_decode(data_stream):
    """Decodes a varint from a bytes stream."""
    shift = 0
    result = 0
    while True:
        byte = data_stream.read(1)
        if not byte:
            raise EOFError("Unexpected EOF while decoding varint")
        byte = ord(byte)
        result |= ((byte & 0x7F) << shift)
        if (byte & 0x80) == 0:
            return result
        shift += 7

def parse_protobuf_message(data_bytes):
    """
    Parses a raw protobuf message (specifically, the Google Authenticator
    MigrationPayload) and extracts OTP account details.
    """
    stream = io.BytesIO(data_bytes)
    otp_entries = []

    while True:
        try:
            tag_byte = stream.read(1)
            if not tag_byte:
                break

            tag_byte = ord(tag_byte)
            field_number = tag_byte >> 3
            wire_type = tag_byte & 0x07

            if field_number == 1 and wire_type == 2:
                message_length = varint_decode(stream)
                otp_params_bytes = stream.read(message_length)
                
                otp_param_stream = io.BytesIO(otp_params_bytes)
                current_otp = {}

                while True:
                    try:
                        inner_tag_byte = otp_param_stream.read(1)
                        if not inner_tag_byte:
                            break
                        inner_tag_byte = ord(inner_tag_byte)
                        inner_field_number = inner_tag_byte >> 3
                        inner_wire_type = inner_tag_byte & 0x07

                        if inner_wire_type == 0:
                            value = varint_decode(otp_param_stream)
                            if inner_field_number == 4:
                                current_otp['type_int'] = value
                            elif inner_field_number == 5:
                                current_otp['algorithm_int'] = value
                            elif inner_field_number == 6:
                                current_otp['digits_int'] = value
                            elif inner_field_number == 8:
                                current_otp['counter_int'] = value

                        elif inner_wire_type == 2:
                            value_length = varint_decode(otp_param_stream)
                            value_bytes = otp_param_stream.read(value_length)

                            if inner_field_number == 1:
                                current_otp['secret_bytes'] = value_bytes
                                current_otp['secret_base32'] = base64.b32encode(value_bytes).decode('utf-8').strip('=')
                            elif inner_field_number == 2:
                                current_otp['name'] = value_bytes.decode('utf-8')
                            elif inner_field_number == 3:
                                current_otp['issuer'] = value_bytes.decode('utf-8')
                        else:
                            pass
                    except EOFError:
                        break
                
                if 'type_int' not in current_otp: current_otp['type_int'] = 1
                if 'algorithm_int' not in current_otp: current_otp['algorithm_int'] = 1
                if 'digits_int' not in current_otp: current_otp['digits_int'] = 6

                otp_entries.append(current_otp)

            else:
                if wire_type == 0:
                    varint_decode(stream)
                elif wire_type == 2:
                    length = varint_decode(stream)
                    stream.read(length)
                elif wire_type == 1:
                    stream.read(8)
                elif wire_type == 5:
                    stream.read(4)

        except EOFError:
            break
        except Exception as e:
            print(f"Error during protobuf parsing: {e}")
            break
            
    return otp_entries

# --- Unified URL Extraction ---

def extract_otp_details_from_url(input_url):
    """
    Extracts OTP account details from either an otpauth-migration URL
    or a direct otpauth://totp/ / otpauth://hotp/ URI.
    """
    parsed_input_url = urlparse(input_url)

    if parsed_input_url.scheme == 'otpauth-migration':
        print("Detected otpauth-migration URL. Parsing as Google Authenticator export.")
        query_params = parse_qs(parsed_input_url.query)
        encoded_data = query_params.get('data', [None])[0]

        if not encoded_data:
            print("Error: No 'data' parameter found in the otpauth-migration URL.")
            return []

        try:
            decoded_base64_bytes = base64.b64decode(unquote(encoded_data))
        except Exception as e:
            print(f"Error decoding base64 data from otpauth-migration URL: {e}")
            return []

        return parse_protobuf_message(decoded_base64_bytes)

    elif parsed_input_url.scheme == 'otpauth':
        print("Detected otpauth:// URI. Parsing as single OTP entry.")
        
        # Try parsing the URI as-is first
        try:
            totp_obj = pyotp.parse_uri(input_url)
            # If successful, map to our internal format
            otp_entry = {
                'secret_base32': totp_obj.secret,
                'name': totp_obj.name,
                'issuer': totp_obj.issuer if totp_obj.issuer else None,
                'type_int': 1 if isinstance(totp_obj, pyotp.TOTP) else 2,
                'digits_int': totp_obj.digits,
                'algorithm_int': 1 # Assuming SHA1, as pyotp defaults to it
            }
            if isinstance(totp_obj, pyotp.HOTP):
                otp_entry['counter_int'] = totp_obj.initial_count
            return [otp_entry]

        except ValueError as e:
            # Check for the specific issuer mismatch error
            if "If issuer is specified in both label and parameters, it should be equal." in str(e):
                print(f"{COLOR_YELLOW}Warning: Issuer mismatch detected in otpauth URI label. Attempting to fix...{COLOR_RESET}")
                
                scheme = parsed_input_url.scheme
                netloc = parsed_input_url.netloc 
                
                original_label_decoded = unquote(parsed_input_url.path.lstrip('/'))
                
                if ':' in original_label_decoded:
                    fixed_label_decoded = original_label_decoded.split(':', 1)[1]
                else:
                    fixed_label_decoded = original_label_decoded

                original_query_string = parsed_input_url.query
                
                fixed_url_path = '/' + quote(fixed_label_decoded, safe='')

                new_uri_components = (
                    scheme,
                    netloc,
                    fixed_url_path,
                    parsed_input_url.params,
                    original_query_string,
                    parsed_input_url.fragment
                )
                fixed_url = urlunparse(new_uri_components)
                
                print(f"{COLOR_DIM}Attempting to parse fixed URI: {fixed_url}{COLOR_RESET}")
                try:
                    totp_obj = pyotp.parse_uri(fixed_url)
                    otp_entry = {
                        'secret_base32': totp_obj.secret,
                        'name': totp_obj.name,
                        'issuer': totp_obj.issuer if totp_obj.issuer else None,
                        'type_int': 1 if isinstance(totp_obj, pyotp.TOTP) else 2,
                        'digits_int': totp_obj.digits,
                        'algorithm_int': 1
                    }
                    if isinstance(totp_obj, pyotp.HOTP):
                        otp_entry['counter_int'] = totp_obj.initial_count
                    return [otp_entry]

                except Exception as retry_e:
                    print(f"{COLOR_RED}Error after fixing URI: {retry_e}{COLOR_RESET}")
                    print(f"{COLOR_RED}Failed to parse otpauth:// URI even after attempted fix. Please check format.{COLOR_RESET}")
                    return []
            else:
                print(f"{COLOR_RED}Error parsing otpauth:// URI: {e}{COLOR_RESET}")
                print(f"Please ensure the URI is correctly formatted. Example: otpauth://totp/Label?secret=ABCDEF1234567890")
                return []
        except Exception as e:
            print(f"{COLOR_RED}An unexpected error occurred while parsing otpauth:// URI: {e}{COLOR_RESET}")
            return []
    else:
        print(f"{COLOR_RED}Error: Unsupported URL scheme '{parsed_input_url.scheme}'. Expected 'otpauth-migration' or 'otpauth'.{COLOR_RESET}")
        return []

# --- Configuration File Management ---

def get_config_path():
    """Returns the path to the configuration file."""
    config_dir = os.path.join(os.path.expanduser('~'), '.config', 'otp_cli')
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, 'otps.json')

def save_otps_to_config(otp_entries, config_path):
    """Saves OTP entries to the specified JSON configuration file."""
    try:
        with open(config_path, 'w') as f:
            serializable_entries = []
            for entry in otp_entries:
                serializable_entry = {
                    'secret_base32': entry.get('secret_base32'),
                    'name': entry.get('name'),
                    'issuer': entry.get('issuer'),
                    'type_int': entry.get('type_int'),
                    'algorithm_int': entry.get('algorithm_int'),
                    'digits_int': entry.get('digits_int'),
                    'counter_int': entry.get('counter_int')
                }
                serializable_entries.append(serializable_entry)
            json.dump(serializable_entries, f, indent=4)
        print(f"OTP accounts saved to {config_path}")
    except Exception as e:
        print(f"{COLOR_RED}Error saving OTPs to config file: {e}{COLOR_RESET}")

def load_otps_from_config(config_path):
    """Loads OTP entries from the specified JSON configuration file."""
    if not os.path.exists(config_path):
        return []
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"{COLOR_RED}Error decoding JSON from config file: {e}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}Config file might be corrupted. Consider deleting '{config_path}' and re-adding accounts.{COLOR_RESET}")
        return []
    except Exception as e:
        print(f"{COLOR_RED}Error loading OTPs from config file: {e}{COLOR_RESET}")
        return []

# --- OTP Display Logic ---

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_progress_bar(seconds_remaining, total_seconds=30, bar_length=20):
    """Generates an ASCII progress bar."""
    progress = total_seconds - seconds_remaining
    filled_chars = int(bar_length * (progress / total_seconds))
    empty_chars = bar_length - filled_chars
    
    bar_color = COLOR_GREEN
    if seconds_remaining <= 10:
        bar_color = COLOR_YELLOW
    if seconds_remaining <= 5:
        bar_color = COLOR_RED

    bar = f"{bar_color}[{'#' * filled_chars}{'-' * empty_chars}]{COLOR_RESET}"
    return bar

def _display_current_otps(totp_accounts):
    """Helper function to print the current OTP codes."""
    for entry in totp_accounts:
        try:
            totp = pyotp.TOTP(entry['secret_base32'])
            code = totp.now()
            label_issuer = entry.get('issuer', '').strip()
            label_name = entry.get('name', '').strip()

            if label_issuer and label_name:
                display_label = f"{COLOR_CYAN}{label_issuer}{COLOR_RESET} ({COLOR_BLUE}{label_name}{COLOR_RESET})"
            elif label_issuer:
                display_label = f"{COLOR_CYAN}{label_issuer}{COLOR_RESET}"
            elif label_name:
                display_label = f"{COLOR_BLUE}{label_name}{COLOR_RESET}"
            else:
                display_label = f"{COLOR_DIM}Unnamed Account{COLOR_RESET}"
            
            sys.stdout.write(f"{display_label}:\n")
            sys.stdout.write(f"  {COLOR_GREEN}{COLOR_BOLD}{code}{COLOR_RESET}\n\n")
        except Exception as e:
            sys.stdout.write(f"{COLOR_RED}Error generating OTP for {entry.get('name', 'unknown')}: {e}{COLOR_RESET}\n\n")
    sys.stdout.write("------------------------------------\n")
    sys.stdout.flush()

def display_otps(otp_entries):
    """
    Continuously displays refreshing TOTP codes.
    """
    if not otp_entries:
        print("No OTP entries loaded. Add accounts using 'python otp_cli.py add <URL>'")
        return

    totp_accounts = [
        entry for entry in otp_entries if entry.get('type_int') == 1
    ]

    if not totp_accounts:
        print("No TOTP accounts found to display continuously.")
        print("Found HOTP accounts (if any) would require explicit counter updates.")
        return

    print(f"{COLOR_BOLD}Generating TOTP codes (Ctrl+C to stop){COLOR_RESET}\n")
    try:
        # Initial display of codes
        clear_screen()
        sys.stdout.write(f"{COLOR_BOLD}Generating TOTP codes (Ctrl+C to stop){COLOR_RESET}\n\n")
        _display_current_otps(totp_accounts)
        
        # Set last_refresh_time to current_time to ensure the next refresh is 30s from now
        # This ensures the progress bar starts correctly after the initial display.
        last_refresh_time = int(time.time())

        while True:
            current_time = int(time.time())
            seconds_remaining = 30 - (current_time % 30)

            # Only refresh codes when it's the precise start of a new 30-second window
            # Check if seconds_remaining is 30, and ensure we haven't just refreshed
            if seconds_remaining == 30: # This means we just entered a new 30-second window
                clear_screen()
                sys.stdout.write(f"{COLOR_BOLD}Generating TOTP codes (Ctrl+C to stop){COLOR_RESET}\n\n")
                _display_current_otps(totp_accounts)
                last_refresh_time = current_time # Update last refresh time
            
            # Always display the progress bar
            progress_bar = get_progress_bar(seconds_remaining)
            sys.stdout.write(f"\r{COLOR_DIM}Next refresh: {seconds_remaining:02d}s {progress_bar}{COLOR_RESET}")
            sys.stdout.flush()

            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n{COLOR_YELLOW}Exiting OTP display.{COLOR_RESET}")

# --- New Function: Get OTP URI for a specific account ---

def get_otp_uri_for_account(otp_entries, search_term):
    """
    Searches for an OTP account by a search term (case-insensitive partial match
    on issuer or name) and prints its otpauth:// URI.
    """
    matching_accounts = []
    search_term_lower = search_term.lower()

    for i, entry in enumerate(otp_entries):
        label_issuer = entry.get('issuer', '').lower()
        label_name = entry.get('name', '').lower()
        
        if search_term_lower in label_issuer or search_term_lower in label_name:
            matching_accounts.append((i, entry))
    
    if not matching_accounts:
        print(f"{COLOR_RED}No account found matching '{search_term}'.{COLOR_RESET}")
        return
    
    if len(matching_accounts) > 1:
        print(f"{COLOR_YELLOW}Multiple accounts found matching '{search_term}':{COLOR_RESET}")
        for idx, (original_idx, entry) in enumerate(matching_accounts):
            display_label = f"{entry.get('issuer', '')}: {entry.get('name', '')}".strip(': ')
            print(f"  {idx+1}. {COLOR_CYAN}{display_label}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}Please refine your search term or specify a more unique part of the label.{COLOR_RESET}")
        return

    # Exactly one match found
    _, account_entry = matching_accounts[0]

    _type = "totp" if account_entry.get('type_int') == 1 else "hotp"
    
    # pyotp's provisioning_uri handles URL encoding and correct label formatting
    # It expects the secret to be a string (base32)
    # It expects name and issuer as strings
    
    try:
        if _type == "totp":
            otp_obj = pyotp.TOTP(
                s=account_entry['secret_base32'],
                digits=account_entry.get('digits_int', 6),
                digest=pyotp.DEFAULT_DIGEST # Assuming SHA1, pyotp handles this
            )
        elif _type == "hotp":
            otp_obj = pyotp.HOTP(
                s=account_entry['secret_base32'],
                digits=account_entry.get('digits_int', 6),
                digest=pyotp.DEFAULT_DIGEST,
                initial_count=account_entry.get('counter_int', 0)
            )
        else:
            print(f"{COLOR_RED}Unsupported OTP type for URI export: {_type}{COLOR_RESET}")
            return

        # Use pyotp's provisioning_uri to construct the URL
        uri = otp_obj.provisioning_uri(
            name=account_entry.get('name', 'Unnamed Account'),
            issuer_name=account_entry.get('issuer', 'Unknown Issuer')
        )
        print(f"\n{COLOR_BOLD}OTP URI for '{search_term}':{COLOR_RESET}")
        print(f"{COLOR_GREEN}{uri}{COLOR_RESET}\n")
        print(f"{COLOR_DIM}You can use this URI to import the account into another authenticator app.{COLOR_RESET}")

    except Exception as e:
        print(f"{COLOR_RED}Error generating URI for account '{search_term}': {e}{COLOR_RESET}")
        print(f"{COLOR_RED}Ensure the account details are complete in the config file.{COLOR_RESET}")


# --- Main CLI Logic ---

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool to manage and display Google Authenticator OTP codes.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--config',
        default=get_config_path(),
        help=f"Specify custom config file path (default: {get_config_path()})"
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Add command
    add_parser = subparsers.add_parser(
        'add',
        help='Add new OTP accounts from an otpauth-migration URL or a direct otpauth:// URI.',
        description='''
        Add new OTP accounts.
        You can provide either:
        1. An `otpauth-migration://offline?data=...` URL (from Google Authenticator export QR).
           Example: python otp_cli.py add "otpauth-migration://offline?data=..."
        2. A direct `otpauth://totp/` or `otpauth://hotp/` URI (e.g., from Microsoft My Sign-ins).
           Example: python otp_cli.py add "otpauth://totp/Label?secret=ABCDEF1234567890&issuer=Example"
        '''
    )
    add_parser.add_argument(
        'url',
        type=str,
        help='The OTP export URL or URI (otpauth-migration:// or otpauth://).'
    )

    # List command
    list_parser = subparsers.add_parser(
        'list',
        help='List currently stored OTP accounts.'
    )

    # Show command (default if no command)
    show_parser = subparsers.add_parser(
        'show',
        help='Display continuously refreshing TOTP codes.'
    )

    # Get-URI command
    get_uri_parser = subparsers.add_parser(
        'get-uri',
        help='Display the otpauth:// URI for a specific stored account.',
        description='''
        Retrieves and displays the otpauth:// URI for a stored account.
        This can be useful for re-importing an account into another authenticator app.
        Provide a search term that matches part of the account's issuer or name.
        If multiple matches are found, it will list them.
        '''
    )
    get_uri_parser.add_argument(
        'search_term',
        type=str,
        help='A search term to identify the account (e.g., "Microsoft", "deloitte.es", "github").'
    )


    args = parser.parse_args()

    config_path = args.config

    if args.command == 'add':
        print("Attempting to parse OTP URL...")
        new_otp_entries = extract_otp_details_from_url(args.url)
        if new_otp_entries:
            print(f"Found {len(new_otp_entries)} new OTP account(s).")
            existing_otps = load_otps_from_config(config_path)
            
            existing_keys = set()
            for entry in existing_otps:
                key = (entry.get('secret_base32'), entry.get('name'), entry.get('issuer'))
                existing_keys.add(key)

            added_count = 0
            for new_entry in new_otp_entries:
                new_key = (new_entry.get('secret_base32'), new_entry.get('name'), new_entry.get('issuer'))
                if new_key not in existing_keys:
                    existing_otps.append(new_entry)
                    added_count += 1
                    print(f"  Added: {new_entry.get('issuer', '')}: {new_entry.get('name', '')}")
                else:
                    print(f"  Skipped (already exists): {new_entry.get('issuer', '')}: {new_entry.get('name', '')}")

            save_otps_to_config(existing_otps, config_path)
            print(f"Added {added_count} unique account(s).")
        else:
            print("Failed to extract any OTP accounts from the provided URL.")
    elif args.command == 'list':
        otp_accounts = load_otps_from_config(config_path)
        if otp_accounts:
            print("\n--- Stored OTP Accounts ---")
            for i, entry in enumerate(otp_accounts):
                _type = "TOTP" if entry.get('type_int') == 1 else "HOTP" if entry.get('type_int') == 2 else "Unknown Type"
                _label = f"{entry.get('issuer', 'Unknown Issuer')}: {entry.get('name', 'Unknown Account')}".strip(': ')
                _digits = entry.get('digits_int', 6)
                _algo = "SHA1" # Simplified, could map from algorithm_int

                print(f"  {i+1}. Label: {COLOR_CYAN}{_label}{COLOR_RESET}")
                print(f"     Type: {_type}, Digits: {_digits}, Algorithm: {_algo}")
                if _type == "HOTP" and 'counter_int' in entry:
                    print(f"     Counter: {entry['counter_int']}")
            print("---------------------------")
        else:
            print("No OTP accounts stored. Use 'add' command to add them.")
    elif args.command == 'get-uri':
        otp_accounts = load_otps_from_config(config_path)
        if not otp_accounts:
            print("No OTP accounts stored. Use 'add' command to add them before trying to get a URI.")
        else:
            get_otp_uri_for_account(otp_accounts, args.search_term)
    else: # Default command is 'show'
        otp_accounts = load_otps_from_config(config_path)
        display_otps(otp_accounts)

if __name__ == "__main__":
    main()
