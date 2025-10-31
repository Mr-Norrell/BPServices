#!/usr/bin/env python3

import argparse
import subprocess
import json
import csv
import os
import time
import random


def call_get_deposit_draft_by_iban(
    url,
    username,
    password,
    draft_date_jalali,
    iban,
    last_id=None,
    extra_headers=None,
    connect_timeout=15,
    request_timeout=60,
):
    """
    Calls the getDepositDraftByIban REST endpoint via curl and returns the output (JSON string).

    Returns:
        str: The response body on success (may append HTTP_STATUS meta line)
        str: Error message with "ERROR:" prefix for permanent errors
        None: For transient errors that should be retried
    """
    if not url:
        print("Error: REST URL is required.")
        return "ERROR: Missing REST URL"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if isinstance(extra_headers, dict):
        headers.update(extra_headers)

    # API sample shows draftDate as a number like 14010914 (Jalali)
    # Convert to int to mirror documentation, but be tolerant if not numeric
    try:
        draft_date_value = int(draft_date_jalali)
    except Exception:
        draft_date_value = draft_date_jalali

    body = {
        "draftDate": draft_date_value,
        "iban": iban,
    }

    # Add id parameter for pagination if provided
    if last_id:
        try:
            body["id"] = int(last_id)
        except Exception:
            body["id"] = last_id

    curl_command = [
        "curl",
        "--silent",  # do not print progress meter
        "--show-error",  # still show errors
        "--location",  # follow redirects
        "--connect-timeout",
        str(connect_timeout),
        "--max-time",
        str(request_timeout),
        "-X",
        "POST",
        url,
        "-H",
        f"Content-Type: {headers['Content-Type']}",
        "-H",
        f"Accept: {headers['Accept']}",
        "-u",
        f"{username}:{password}",
        "-d",
        json.dumps(body),
        "-w",
        "\nHTTP_STATUS:%{http_code}\nCONTENT_TYPE:%{content_type}\n",
    ]

    print("Executing REST curl command...")
    try:
        python_timeout = request_timeout + 10
        process = subprocess.run(
            curl_command,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            timeout=python_timeout,
        )
        stdout_text = process.stdout or ""
        stderr_text = process.stderr or ""

        # Extract status meta from stdout
        http_status = None
        content_type = None
        if "HTTP_STATUS:" in stdout_text:
            parts = stdout_text.split("\n")
            body_lines = []
            for line in parts:
                if line.startswith("HTTP_STATUS:"):
                    try:
                        http_status = int(line.split(":", 1)[1].strip())
                    except Exception:
                        http_status = None
                    continue
                if line.startswith("CONTENT_TYPE:"):
                    content_type = line.split(":", 1)[1].strip()
                    continue
                body_lines.append(line)
            stdout_text = "\n".join(body_lines).rstrip("\n")

        # curl exit code handling
        if process.returncode != 0:
            curl_exit_code = process.returncode

            transient_curl_errors = {
                7: "Failed to connect",
                28: "Operation timeout",
                35: "SSL connect error",
                52: "Empty reply from server",
                56: "Failure in receiving network data",
                60: "Peer certificate cannot be authenticated",
            }
            permanent_curl_errors = {
                1: "Unsupported protocol",
                3: "URL malformed",
                5: "Couldn't resolve proxy",
                6: "Couldn't resolve host",
                22: "HTTP page not retrieved (404, etc)",
                51: "SSL peer certificate or SSH remote key was not OK",
                67: "Login denied",
            }

            if curl_exit_code in transient_curl_errors:
                print(f"Transient error: curl({curl_exit_code}) - {transient_curl_errors[curl_exit_code]}")
                return None
            if curl_exit_code in permanent_curl_errors:
                print(f"Permanent error: curl({curl_exit_code}) - {permanent_curl_errors[curl_exit_code]}")
                return f"ERROR: curl({curl_exit_code}) - {permanent_curl_errors[curl_exit_code]}"

            transient_patterns = [
                "unexpected eof while reading",
                "connection reset by peer",
                "timeout",
                "connection refused",
                "network unreachable",
                "ssl handshake failure",
            ]
            if stderr_text and any(p in stderr_text.lower() for p in transient_patterns):
                print(f"Transient network error: {stderr_text.strip()}")
                return None
            print(f"Unknown curl error ({curl_exit_code}): {stderr_text.strip()}")
            return f"ERROR: curl({curl_exit_code}) - {stderr_text.strip()}"

        # HTTP status handling
        if http_status is not None:
            print(f"REST status: {http_status} ({content_type or 'unknown content-type'})")
            if 200 <= http_status < 300:
                print("REST curl command executed successfully.")
                stdout_text += f"\nHTTP_STATUS:{http_status}"
            elif http_status == 429:
                print("Rate limit exceeded.")
                stdout_text += f"\nHTTP_STATUS:{http_status}"
            elif http_status >= 500:
                print(f"Server error: HTTP {http_status}")
                return None
            elif 400 <= http_status < 500:
                print(f"Client error: HTTP {http_status}")
                return f"ERROR: HTTP {http_status} - Client error"
            else:
                stdout_text += f"\nHTTP_STATUS:{http_status}"
        else:
            print("REST curl command completed but no HTTP status was returned.")

        if not stdout_text.strip() and stderr_text.strip():
            print("Note: Empty stdout; using stderr as response body.")
            return stderr_text

        if not stdout_text.strip():
            print("Warning: Empty response body.")
            return None

        # Validate JSON (strip HTTP status meta first)
        json_to_validate = stdout_text
        if "\nHTTP_STATUS:" in json_to_validate:
            json_to_validate = json_to_validate.split("\nHTTP_STATUS:")[0]
        try:
            json.loads(json_to_validate)
        except json.JSONDecodeError:
            print("Warning: Response is not valid JSON. This might indicate a partial or corrupted response.")
            if len(json_to_validate) < 500:
                print(f"Invalid JSON response: {json_to_validate}")
            return None

        return stdout_text

    except subprocess.TimeoutExpired:
        print(f"Request timed out after {python_timeout} seconds (Python timeout)")
        return None
    except FileNotFoundError:
        print("Error: curl command not found. Please ensure curl is installed and in your PATH.")
        return "ERROR: curl command not found"
    except Exception as e:
        print(f"Unexpected error during REST curl execution: {str(e)}")
        return None


def retry_with_backoff(
    func,
    *args,
    max_retries=3,
    initial_delay=2,
    backoff_factor=2,
    error_type="Unknown error",
    **kwargs,
):
    """
    Execute a function with retry logic and exponential backoff.

    Returns the function result, or None if all retries failed.
    """
    delay = initial_delay
    result = None

    for attempt in range(max_retries + 1):
        if attempt > 0:
            jitter = random.uniform(0.8, 1.2)
            actual_delay = delay * jitter
            print(f"{error_type}. Retrying in {actual_delay:.1f} seconds (attempt {attempt}/{max_retries})...")
            time.sleep(actual_delay)
            delay *= backoff_factor

        try:
            result = func(*args, **kwargs)

            if isinstance(result, str) and "HTTP_STATUS:429" in result:
                error_type = "Rate limit exceeded"
                continue

            if result is None or (isinstance(result, str) and not result.strip()):
                error_type = "Empty response received"
                continue

            transient_errors = [
                "unexpected eof while reading",
                "connection reset by peer",
                "timeout",
                "connection refused",
                "network unreachable",
                "ssl handshake failure",
            ]
            if isinstance(result, str) and any(err in result.lower() for err in transient_errors):
                error_type = "Transient network error"
                continue

            return result

        except Exception as e:
            error_type = f"Exception: {str(e)}"
            result = None
            continue

    print(f"Failed after {max_retries} retries due to: {error_type}")
    return result


def parse_deposit_json_to_csv(json_output, csv_filename):
    """
    Parses a JSON response from getDepositDraftByIban and writes depositInfoList to a CSV file.
    Returns True on success, False otherwise.
    """
    if not json_output:
        print("No JSON output to parse.")
        return False

    try:
        parsed = json.loads(json_output)

        if isinstance(parsed, dict):
            success = parsed.get("success")
            response_code = parsed.get("responseCode")
            response_message = parsed.get("responseMessage")
            if success is not None:
                print(f"Success: {success}")
            if response_code is not None or response_message is not None:
                print(f"Status: Code='{response_code}', Message='{response_message}'")

            records = parsed.get("depositInfoList")
            if isinstance(records, list) and records:
                header = list(records[0].keys())
                with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=header)
                    writer.writeheader()
                    for item in records:
                        row = {h: (item.get(h, "") if isinstance(item, dict) else "") for h in header}
                        writer.writerow(row)
                print(f"Successfully converted JSON data to {csv_filename}")
                print(f"Retrieved {len(records)} records")
                return True

            # Fallback: write top-level dict as single row
            header = list(parsed.keys())
            with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header)
                writer.writeheader()
                writer.writerow({h: parsed.get(h, "") for h in header})
            print(f"Wrote single-row JSON dictionary to {csv_filename}")
            return True

        if isinstance(parsed, list) and parsed:
            header = list(parsed[0].keys()) if isinstance(parsed[0], dict) else ["value"]
            with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header)
                writer.writeheader()
                for item in parsed:
                    if isinstance(item, dict):
                        writer.writerow({h: item.get(h, "") for h in header})
                    else:
                        writer.writerow({"value": item})
            print(f"Successfully converted JSON array to {csv_filename}")
            return True

        print("JSON did not contain recognizable deposit data.")
        return False

    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        print("Problematic JSON (first 1000 chars):", json_output[:1000])
        return False
    except Exception as e:
        print(f"An unexpected error occurred during JSON parsing or CSV writing: {e}")
        return False


def sanitize_iban_for_filename(iban):
    # Keep alphanumerics, replace others with '_'
    safe = []
    for ch in iban:
        if ch.isalnum():
            safe.append(ch)
        else:
            safe.append("_")
    return "".join(safe)


def main():
    parser = argparse.ArgumentParser(
        description="Call getDepositDraftByIban REST API and convert output to CSV.",
        epilog=(
            "Authentication: Uses HTTP Basic Auth (Authorization header).\n"
            "Pagination: Use --AutoPaginate to follow 'id' and fetch subsequent pages.\n"
            "Dates: draftDate must be Jalali (YYYYMMDD), as per documentation."
        ),
    )

    parser.add_argument("--Username", "-U", default="RSarmaye1402", help="Username for Basic Auth")
    parser.add_argument("--Password", "-P", default="12021453", help="Password for Basic Auth")
    parser.add_argument("--Iban", required=True, help="Destination IBAN (e.g., IR..)")
    parser.add_argument(
        "--DraftDate",
        "-D",
        required=True,
        help="Draft date in Jalali YYYYMMDD (e.g., 14010914)",
    )
    parser.add_argument("--LastId", "-I", help="Last id for pagination (fetch items after this id)")
    parser.add_argument("--AutoPaginate", action="store_true", help="Automatically paginate through all results using id")
    parser.add_argument("--MaxPages", type=int, default=10, help="Maximum pages to fetch when using AutoPaginate (default: 10)")
    parser.add_argument(
        "--RestUrl",
        default="https://bos.bpm.bankmellat.ir/bhrws/transactionInfo/getDepositDraftByIban",
        help="REST endpoint URL",
    )
    parser.add_argument("--Delay", type=float, default=3, help="Delay in seconds between API requests (default: 3)")
    parser.add_argument("--MaxRetries", type=int, default=3, help="Maximum retries for failed API requests (default: 3)")
    parser.add_argument("--ConnectTimeout", type=int, default=15, help="Connection timeout in seconds for curl (default: 15)")
    parser.add_argument("--RequestTimeout", type=int, default=60, help="Maximum time in seconds for each API request (default: 60)")

    args = parser.parse_args()

    # Prepare output filename
    iban_safe = sanitize_iban_for_filename(args.Iban)
    if args.LastId:
        csv_filename = f"{iban_safe}-{args.DraftDate}-after-{args.LastId}.csv"
    else:
        csv_filename = f"{iban_safe}-{args.DraftDate}.csv"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_filepath = os.path.join(script_dir, csv_filename)

    # Collect responses (may be multiple pages)
    all_json_responses = []

    # Single call (or first page)
    current_last_id = args.LastId
    page_count = 0
    has_more_data = True
    consecutive_failures = 0
    max_consecutive_failures = 3

    while has_more_data:
        page_count += 1

        if args.AutoPaginate and page_count > args.MaxPages:
            print(f"Reached maximum number of pages ({args.MaxPages}). Stopping pagination.")
            break

        if page_count > 1:
            delay_with_jitter = args.Delay * random.uniform(0.9, 1.1)
            print(f"Waiting {delay_with_jitter:.1f} seconds before next request...")
            time.sleep(delay_with_jitter)

        if args.AutoPaginate and page_count > 1:
            print(f"Auto-paginating: Requesting page {page_count} (after id: {current_last_id})")
        elif current_last_id:
            print(f"Requesting data (after id: {current_last_id})")
        else:
            print("Requesting data")

        json_response = retry_with_backoff(
            call_get_deposit_draft_by_iban,
            args.RestUrl,
            args.Username,
            args.Password,
            args.DraftDate,
            args.Iban,
            current_last_id,
            None,
            args.ConnectTimeout,
            args.RequestTimeout,
            max_retries=args.MaxRetries,
            initial_delay=3,
            backoff_factor=2,
            error_type="API request failed",
        )

        if isinstance(json_response, str) and json_response.startswith("ERROR:"):
            print(f"Permanent error received: {json_response}")
            break

        if json_response and not json_response.startswith("ERROR:"):
            # Strip HTTP_STATUS meta
            if "\nHTTP_STATUS:" in json_response:
                json_response = json_response.split("\nHTTP_STATUS:")[0]

            all_json_responses.append(json_response)

            # Determine whether to continue
            if not args.AutoPaginate:
                break

            try:
                parsed = json.loads(json_response)
                records = parsed.get("depositInfoList", [])
                if not records:
                    print("No records in response. Ending pagination.")
                    has_more_data = False
                else:
                    # find last id
                    last_item = records[-1]
                    next_id = last_item.get("id")
                    print(f"Retrieved {len(records)} records; last id: {next_id}")
                    if next_id and len(records) >= 1000:
                        current_last_id = next_id
                        has_more_data = True
                    else:
                        has_more_data = False
            except Exception as e:
                print(f"Error inspecting response for pagination: {e}")
                has_more_data = False

            consecutive_failures = 0
        else:
            # transient error or no response
            consecutive_failures += 1
            print(f"Request failed (attempt {consecutive_failures}/{max_consecutive_failures})")
            if consecutive_failures >= max_consecutive_failures:
                print("Reached maximum consecutive failures. Stopping.")
                break
            retry_delay = args.Delay * (consecutive_failures + 1) * random.uniform(1.0, 1.5)
            print(f"Transient error occurred. Will retry in {retry_delay:.1f} seconds...")
            time.sleep(retry_delay)

    # Write the last page or merge? For simplicity, write only the last complete page if multiple.
    # Here we merge pages by concatenating their arrays before writing.
    if not all_json_responses:
        print("Failed to get any valid responses from the REST API.")
        return

    try:
        merged = None
        for idx, js in enumerate(all_json_responses):
            data = json.loads(js)
            if merged is None:
                merged = data
                # Normalize to ensure list exists
                if isinstance(merged, dict) and "depositInfoList" in merged and not isinstance(merged["depositInfoList"], list):
                    merged["depositInfoList"] = [merged["depositInfoList"]]
            else:
                if isinstance(data, dict):
                    lst = data.get("depositInfoList", [])
                    if isinstance(lst, list):
                        merged.setdefault("depositInfoList", [])
                        merged["depositInfoList"].extend(lst)
        if merged is None:
            print("Nothing to write to CSV.")
            return
        parse_deposit_json_to_csv(json.dumps(merged), csv_filepath)
    except Exception as e:
        print(f"Failed to merge/write responses: {e}")


if __name__ == "__main__":
    main()


