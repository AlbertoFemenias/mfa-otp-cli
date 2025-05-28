# mfa-otp-cli
*Tired of reaching your personal phone during workours to enter MFA codes?*

A simple Python command-line interface (CLI) tool to manage and display Multi-Factor Authentication (MFA) Time-based One-Time Passwords (TOTP) from various sources. This allows you to have your MFA codes accessible directly in your terminal (e.g., in WSL) alongside your phone.

**Disclaimer:** Storing MFA secrets on your computer, even in a configuration file, inherently carries more risk than keeping them solely on your phone. Ensure your system is secure, and understand the security implications before using this tool.

---

## TLDR;

**Add Google Authenticator accounts (batch import):**
`python otp_cli.py add "otpauth-migration://offline?data=..."`

**Add Microsoft Authenticator/single account:**
`python otp_cli.py add "otpauth://totp/Label?secret=ABCDEF1234567890&issuer=Example"`

**Display codes:**
`python otp_cli.py show` (Press `Ctrl+C` to stop)

**Get URI for a stored account:**
`python otp_cli.py get-uri "Microsoft"`

---

## Features

* **Import from Authenticator Apps:** Easily add accounts by providing `otpauth-migration://` URLs (from Google Authenticator exports) or direct `otpauth://` URIs (common for services like Microsoft).
* **Intelligent URI Parsing:** Automatically attempts to fix common `otpauth://` URI issues, such as issuer conflicts between the label and query parameters.
* **Continuous Display:** Shows continuously refreshing TOTP codes directly in your terminal with a clean, colored interface and a progress bar.
* **Export URI:** Retrieve the `otpauth://` URI for any stored account, useful for re-importing into other authenticator apps.
* **Configuration File:** Stores your OTP secrets securely in a local JSON file (in `~/.config/mfa_otp_cli/`).

---

## Prerequisites

* **Python 3.6+**
* **`pyotp` library:** For OTP generation.
* **A QR code scanner:** (e.g., `zbarimg` on Linux/WSL, or an online QR scanner) to extract `otpauth-migration://` URLs from your phone's export QR code.

---

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AlbertoFemenias/mfa-otp-cli.git
    cd mfa-otp-cli
    ```

2.  **Install Python dependencies:**
    It's recommended to use a **virtual environment** to keep your project dependencies separate.
    ```bash
    python -m venv venv
    source venv/bin/activate  ` On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

---

## How to Extract OTP URIs

This tool supports two main types of OTP URIs:

### A. Google Authenticator Export (Batch Import - `otpauth-migration://`)

This method allows you to export **multiple accounts** from Google Authenticator at once.

1.  **On your phone:**
    * Open the **Google Authenticator** app.
    * Tap the three dots (or hamburger menu) in the top right/left corner.
    * Select **"Transfer accounts"**.
    * Choose **"Export accounts"**.
    * Select the accounts you wish to export. You might need to authenticate with your phone's PIN or fingerprint.
    * A **QR code** (or multiple QR codes if you have many accounts) will be displayed. This QR code contains the `otpauth-migration://offline?data=...` URL.
    * Take a screenshot and close the app.

2.  **Extract the URL from the QR code:**
    #### Option A: Using offline desktop QR code scanner

    #### Option B: Using an Online QR Scanner
    * Take the **screenshot** of the QR code on your phone.
    * Go to a reputable online QR code scanner website (e.g., `webqr.com`, `zxing.org/w/decode.jsp`).
    * Upload your screenshot.
    * The website will decode the QR code and display the `otpauth-migration://offline?data=...` URL. **Copy this entire string.**

### B. Microsoft Authenticator / Other Services (Single Account - `otpauth://`)

Many services (including Microsoft) provide a **single `otpauth://` URI** when you set up an authenticator app, especially if you choose a "manual setup" or "can't scan QR code" option.

1.  **On your computer/browser (for Microsoft):**
    * Go to your Microsoft "My Sign-ins" page: `https://mysignins.microsoft.com/security-info`
    * Sign in with your Microsoft account credentials.
    * Under "Security info," click **"+ Add method"**.
    * Choose **"Authenticator app"** from the dropdown menu and click **"Add"**.
    * Click **"Next"** on the "Start by getting the app" screen.
    * **Crucial Step:** On the "Set up your account" screen where a QR code is displayed, look for a small text link below the QR code that says something like:
        * "Set up Authenticator app without push notifications"
        * "Can't scan the QR code?"
        * "Set up manually"
    * Clicking this link will typically reveal the "Manual setup" details, including the **`otpauth://totp/...`** URI (sometimes labeled "URL" or "Secret Key"). **Copy this entire URI.**
    * You will need to configure the URI into this cli with the `python otp_cli.py add "otpauth://totp/Label?secret=ABCDEF1234567890&issuer=Example"` command and then enter the first code on the mysignins page to set up the MFA device (you can not have the same codes in the cli as in the phone like we explained for Google, for Microsoft you must setup a second device).


2.  **For other services:**
    * When setting up 2FA, always look for "manual setup", "enter key manually", or "can't scan QR code?" options. These often reveal the `otpauth://` URI or just the base32 secret. If only the base32 secret is provided, you'll need to manually construct the URI in the format: `otpauth://totp/LABEL?secret=YOUR_BASE32_SECRET&issuer=ISSUER_NAME` (replace `LABEL` and `ISSUER_NAME` appropriately).

---

## Usage

Once you have your OTP URI(s), you can use the CLI tool.

### Command Examples:

```bash
# Add a Google Authenticator export URL (batch import)
python otp_cli.py add "otpauth-migration://offline?data=CkgKCkVzDWRvVcPXkPUSHGFmZW1lbmlhc2hlcm1pZGFAZGVsb2l0dGUuZXMaFmRlbG9pdHRlY2xvdWQub3tLYS5jb20gASgBMAIQAhgBIAA%3D"

# Add a Microsoft Authenticator/single account URI
python otp_cli.py add "otpauth://totp/issuer%3aaccount?secret=wcngxio7ptwklf56&issuer=Microsoft"

# List all currently stored OTP accounts
python otp_cli.py list

# Display continuously refreshing TOTP codes
# Press Ctrl+C to stop the display
python otp_cli.py show

# Get the otpauth:// URI for a specific stored account (e.g., "Microsoft")
python otp_cli.py get-uri "Microsoft"
```

### Add Accounts

Use the `add` command with the URL you extracted.

**Important:** Always enclose the URL/URI in **double quotes (`"`)** to prevent shell interpretation of special characters.

Your OTP accounts will be parsed and saved to `~/.config/mfa_otp_cli/otps.json`.

### List Stored Accounts

To see all accounts currently stored in your configuration file:

```bash
python otp_cli.py list
```

### Display OTP Codes

To continuously display your TOTP codes with a real-time updating interface:

```bash
python otp_cli.py show
```

The terminal will clear, and your codes will be displayed, refreshing every 30 seconds with a progress bar. Press `Ctrl+C` to stop the execution.

### Get OTP URI for a Stored Account

If you need to retrieve the `otpauth://` URI for an account you've already added (e.g., to import it into another authenticator app), use the `get-uri` command:

```bash
python otp_cli.py get-uri "YOUR_SEARCH_TERM"
```
Replace `"YOUR_SEARCH_TERM"` with a unique part of the account's issuer or name (e.g., `"Microsoft"`, `"github"`). If multiple accounts match, the tool will list them and prompt you to refine your search.

### Review the Configuration File

Your OTP secrets are stored in a JSON file:
`~/.config/mfa_otp_cli/otps.json`

You can inspect its contents using a text editor or `cat`:
```bash
cat ~/.config/mfa_otp_cli/otps.json
```
**Be extremely careful with this file as it contains sensitive data.**

---

## Security Considerations

* **Sensitive Data:** The `otps.json` file contains your MFA secrets in a readable (though base32 encoded) format. **Protect this file diligently.** Anyone gaining access to it could generate your MFA codes.
* **File Permissions:** Ensure the `~/.config/mfa_otp_cli/otps.json` file has **strict permissions** (e.g., `chmod 600 ~/.config/mfa_otp_cli/otps.json`) so only your user can read it.
* **Shell History:** Be mindful that pasting sensitive URLs/URIs directly into your shell might save them in your shell history. Consider clearing your history or using methods that prevent history logging if this is a concern.
* **Encryption:** For highly sensitive scenarios, you might want to consider implementing encryption for the `otps.json` file, requiring a password to decrypt it before displaying codes. This tool does not currently offer built-in encryption.

---

## Contributing

Feel free to open issues or submit pull requests if you have suggestions or improvements!

---

## License

*(You might want to add a `LICENSE` file, e.g., MIT License, to your repository for clarity on how others can use your code.)*