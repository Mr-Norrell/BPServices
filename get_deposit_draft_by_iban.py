#!/usr/bin/env python3

import argparse
import subprocess
import json
import csv
import os
import time
import random
import signal
import atexit
from datetime import datetime, timedelta

# Global variables for graceful shutdown
current_csv_file = None
current_csv_writer = None
total_records_processed = 0
last_processed_id = None
shutdown_requested = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested, current_csv_file, total_records_processed, last_processed_id
    
    signal_names = {signal.SIGINT: "SIGINT (Ctrl+C)", signal.SIGTERM: "SIGTERM"}
    signal_name = signal_names.get(signum, f"Signal {signum}")
    
    print(f"\n🛑 Received {signal_name}. Gracefully shutting down...")
    shutdown_requested = True
    
    if current_csv_file:
        print(f"💾 Finalizing output file: {current_csv_file}")
        print(f"📊 Total deposit records processed so far: {total_records_processed}")
        if last_processed_id:
            print(f"🔗 Last processed record ID: {last_processed_id}")
            print(f"📝 To continue from where you left off, use: --LastId {last_processed_id}")
    
    # Don't exit immediately - let the main loop handle cleanup
    return

def cleanup_on_exit():
    """Cleanup function called on normal exit."""
    global current_csv_file, current_csv_writer
    if current_csv_writer:
        try:
            # Ensure any buffered data is written
            current_csv_writer = None
        except:
            pass

def parse_date(date_str):
    """Parse a date string in YYYYMMDD format to a datetime object."""
    try:
        return datetime.strptime(date_str, '%Y%m%d')
    except ValueError as e:
        print(f"Error parsing date {date_str}: {e}")
        return None


def format_date(date_obj):
    """Format a datetime object to YYYYMMDD string."""
    return date_obj.strftime('%Y%m%d')


def split_date_range(from_date_str, to_date_str):
    """Split a date range into daily chunks since the API only accepts single days."""
    from_date = parse_date(from_date_str)
    to_date = parse_date(to_date_str)
    
    if not from_date or not to_date:
        return []
    
    if from_date > to_date:
        print(f"Error: FromDate {from_date_str} is after ToDate {to_date_str}")
        return []
    
    # Generate daily chunks
    chunks = []
    current_date = from_date
    
    while current_date <= to_date:
        date_str = format_date(current_date)
        chunks.append(date_str)
        current_date += timedelta(days=1)
    
    return chunks


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


def write_deposit_chunk_to_csv_incremental(json_response, csv_filepath, is_first_chunk=False):
    """
    Writes a single JSON response chunk to CSV file incrementally for deposit data.
    
    Args:
        json_response: JSON string response from getDepositDraftByIban API
        csv_filepath: Path to the CSV output file
        is_first_chunk: If True, creates new file with header; if False, appends to existing file
        
    Returns:
        dict: Processing statistics including success status, record count, and last ID
    """
    global current_csv_file, current_csv_writer, total_records_processed, last_processed_id
    
    if not json_response:
        return {'success': False, 'error': 'No JSON response provided', 'record_count': 0}
    
    try:
        # Remove HTTP status information if present
        json_to_parse = json_response
        if "\nHTTP_STATUS:" in json_to_parse:
            json_to_parse = json_to_parse.split("\nHTTP_STATUS:")[0]
            
        parsed = json.loads(json_to_parse)
        
        # Extract deposit record list
        records = parsed.get('depositInfoList', [])
        if not records:
            print("  No deposit records in this chunk")
            return {'success': True, 'record_count': 0, 'last_id': last_processed_id}
        
        # Get header from first record
        header = list(records[0].keys())
        
        # Find ID field for tracking
        id_field = next((field for field in ['id', 'Id', 'depositId', 'depositID', 'deposit_id'] 
                       if field in records[-1]), None)
        
        # Open CSV file (create new or append)
        mode = 'w' if is_first_chunk else 'a'
        with open(csv_filepath, mode, newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            
            # Write header only for the first chunk
            if is_first_chunk:
                writer.writeheader()
                current_csv_file = csv_filepath
                print(f"📁 Created output file: {csv_filepath}")
            
            # Write all records from this chunk
            chunk_count = 0
            for item in records:
                row = {h: (item.get(h, '') if h in item else '') for h in header}
                writer.writerow(row)
                chunk_count += 1
                total_records_processed += 1
            
            # Update last processed ID
            if id_field and records:
                last_processed_id = records[-1].get(id_field)
        
        print(f"  ✅ Wrote {chunk_count} deposit records to CSV (Total: {total_records_processed})")
        
        return {
            'success': True,
            'record_count': chunk_count,
            'last_id': last_processed_id,
            'total_processed': total_records_processed
        }
        
    except json.JSONDecodeError as e:
        print(f"  ❌ Error parsing JSON chunk: {e}")
        return {'success': False, 'error': f'JSON parse error: {e}', 'record_count': 0}
    except Exception as e:
        print(f"  ❌ Error writing chunk to CSV: {e}")
        return {'success': False, 'error': str(e), 'record_count': 0}


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
    global shutdown_requested, current_csv_file, total_records_processed, last_processed_id
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # kill command
    atexit.register(cleanup_on_exit)
    
    parser = argparse.ArgumentParser(
        description="Call getDepositDraftByIban REST API and convert output to CSV.",
        epilog=(
            "Authentication: Uses HTTP Basic Auth (Authorization header).\n"
            "Pagination: Use --AutoPaginate to follow 'id' and fetch subsequent pages.\n"
            "Dates: Use --DraftDate for single day or --FromDate/--ToDate for date ranges. All dates must be Jalali (YYYYMMDD).\n"
            "Date ranges: API only accepts single days, so date ranges are split into daily requests automatically."
        ),
    )

    parser.add_argument("--Username", "-U", default="RSarmaye1402", help="Username for Basic Auth")
    parser.add_argument("--Password", "-P", default="12021453", help="Password for Basic Auth")
    parser.add_argument("--Iban", required=True, help="Destination IBAN (e.g., IR..)")
    parser.add_argument(
        "--FromDate",
        "-F",
        help="From Date in Jalali YYYYMMDD format (defaults to ToDate if not provided)",
    )
    parser.add_argument(
        "--ToDate",
        "-O",
        required=True,
        help="To Date in Jalali YYYYMMDD format",
    )
    parser.add_argument(
        "--DraftDate",
        "-D",
        help="Single draft date in Jalali YYYYMMDD (e.g., 14010914) - alternative to FromDate/ToDate range",
    )
    parser.add_argument("--LastId", "-I", help="Last id for pagination (fetch items after this id)")
    parser.add_argument("--AutoPaginate", action="store_true", help="Automatically paginate through all results using id")
    parser.add_argument("--MaxPages", type=int, default=10, help="Maximum pages to fetch when using AutoPaginate (default: 10, use 0 for unlimited)")
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

    # Handle date arguments - support both single DraftDate and FromDate/ToDate range
    if args.DraftDate:
        # Single date mode
        from_date = args.DraftDate
        to_date = args.DraftDate
        print(f"Using single draft date: {args.DraftDate}")
    else:
        # Date range mode
        if not args.ToDate:
            print("Error: Either --DraftDate or --ToDate must be provided.")
            return
        
        # Set FromDate to ToDate if FromDate is not provided
        if args.FromDate is None:
            args.FromDate = args.ToDate
            print(f"FromDate not provided, defaulting to ToDate: {args.FromDate}")
        
        from_date = args.FromDate
        to_date = args.ToDate

    # Date format validation
    if not (len(to_date) == 8 and to_date.isdigit()):
        print("Error: ToDate must be in YYYYMMDD format.")
        return
    if not (len(from_date) == 8 and from_date.isdigit()):
        print("Error: FromDate must be in YYYYMMDD format.")
        return

    # Prepare output filename
    iban_safe = sanitize_iban_for_filename(args.Iban)
    if args.LastId:
        csv_filename = f"{iban_safe}-{from_date}-{to_date}-after-{args.LastId}.csv"
    else:
        csv_filename = f"{iban_safe}-{from_date}-{to_date}.csv"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_filepath = os.path.join(script_dir, csv_filename)

    # Split date range into daily chunks since API only accepts single days
    date_chunks = split_date_range(from_date, to_date)
    
    if not date_chunks:
        print("Failed to process date range. Please check your date format.")
        return
        
    if len(date_chunks) > 1:
        print(f"Date range spans {len(date_chunks)} days. Processing each day separately:")
        for i, date_str in enumerate(date_chunks):
            print(f"  Day {i+1}: {date_str}")
    
    # Use the delay specified in command line arguments
    delay_between_requests = args.Delay
    
    # Track processing state for incremental output
    is_first_chunk_written = False
    total_chunks_processed = 0
    
    print(f"🚀 Starting incremental processing of {len(date_chunks)} date(s)")
    print(f"📄 Output will be written incrementally to: {csv_filepath}")
    
    # Handle each date chunk
    for chunk_idx, current_draft_date in enumerate(date_chunks):
        # Check for shutdown signal before processing each date
        if shutdown_requested:
            print(f"\n🛑 Shutdown requested. Stopping at date {chunk_idx+1}/{len(date_chunks)}")
            break
            
        if chunk_idx > 0:
            print(f"\n--- Processing date {chunk_idx+1}/{len(date_chunks)}: {current_draft_date} ---")
        
        current_last_id = args.LastId  # Start with user-provided LastId if any
        page_count = 0
        has_more_data = True
        
        # Loop for auto-pagination within this date
        consecutive_failures = 0
        max_consecutive_failures = 3
        last_successful_id = current_last_id  # Keep track of the last successful ID
        
        while has_more_data and not shutdown_requested:
            page_count += 1

            # Check page limit (0 means unlimited)
            if args.AutoPaginate and args.MaxPages > 0 and page_count > args.MaxPages:
                print(f"Reached maximum number of pages ({args.MaxPages}). Stopping pagination.")
                break

            # Add delay between requests to avoid rate limiting, except for the first request
            if page_count > 1 or chunk_idx > 0:
                delay_with_jitter = delay_between_requests * random.uniform(0.9, 1.1)
                print(f"Waiting {delay_with_jitter:.1f} seconds before next request...")
                time.sleep(delay_with_jitter)

            if args.AutoPaginate and page_count > 1:
                print(f"Auto-paginating: Requesting page {page_count} for date {current_draft_date} (after id: {current_last_id})")
            elif current_last_id:
                print(f"Requesting data for date {current_draft_date} (after id: {current_last_id})")
            else:
                print(f"Requesting data for date: {current_draft_date}")

            json_response = retry_with_backoff(
                call_get_deposit_draft_by_iban,
                args.RestUrl,
                args.Username,
                args.Password,
                current_draft_date,  # Use the current date from the chunk
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

            # Check if the response is a permanent error (starts with ERROR:)
            if isinstance(json_response, str) and json_response.startswith("ERROR:"):
                print(f"Permanent error received: {json_response}")
                # For permanent errors, we should stop trying
                has_more_data = False
                break

            # Check if we got a valid response
            if json_response and not json_response.startswith("ERROR:"):
                # Reset consecutive failures counter on success
                consecutive_failures = 0
                
                # Write this chunk immediately to CSV
                write_result = write_deposit_chunk_to_csv_incremental(
                    json_response, 
                    csv_filepath, 
                    is_first_chunk=(not is_first_chunk_written)
                )
                
                if write_result['success']:
                    if not is_first_chunk_written:
                        is_first_chunk_written = True
                    
                    # Determine whether to continue with pagination
                    if not args.AutoPaginate:
                        has_more_data = False
                    else:
                        try:
                            # Remove HTTP status info for parsing
                            json_to_parse = json_response
                            if "\nHTTP_STATUS:" in json_to_parse:
                                json_to_parse = json_to_parse.split("\nHTTP_STATUS:")[0]
                                
                            parsed = json.loads(json_to_parse)
                            records = parsed.get("depositInfoList", [])
                            if not records:
                                print("  No records in response. Ending pagination.")
                                has_more_data = False
                            else:
                                # Find last id for pagination
                                last_item = records[-1]
                                next_id = last_item.get("id")
                                print(f"  Retrieved {len(records)} records; last id: {next_id}")
                                if next_id and len(records) >= 1000:
                                    current_last_id = next_id
                                    last_successful_id = next_id
                                    has_more_data = True
                                else:
                                    print(f"  Retrieved {len(records)} records (less than 1000). End of data reached.")
                                    has_more_data = False
                        except Exception as e:
                            print(f"  Error inspecting response for pagination: {e}")
                            has_more_data = False
                else:
                    print(f"  ❌ Failed to write chunk: {write_result.get('error', 'Unknown error')}")
                    # Continue with next request even if this chunk failed to write
            else:
                # transient error or no response
                consecutive_failures += 1
                print(f"Request failed (attempt {consecutive_failures}/{max_consecutive_failures})")
                if consecutive_failures >= max_consecutive_failures:
                    print(f"Reached maximum consecutive failures ({max_consecutive_failures}). Stopping pagination for this date.")
                    
                    # If we had at least one successful response before, we can continue from the last successful ID
                    if last_successful_id and last_successful_id != args.LastId:
                        print(f"Will use last successful ID ({last_successful_id}) for the next date if available.")
                        current_last_id = last_successful_id
                    
                    has_more_data = False
                else:
                    # For transient errors, add a longer delay before retrying
                    retry_delay = delay_between_requests * (consecutive_failures + 1) * random.uniform(1.0, 1.5)
                    print(f"Transient error occurred. Will retry in {retry_delay:.1f} seconds...")
                    time.sleep(retry_delay)
        
        total_chunks_processed += 1
        
        # Check for shutdown signal after each date
        if shutdown_requested:
            print(f"\n🛑 Shutdown requested after processing date {chunk_idx+1}/{len(date_chunks)}")
            break
            
    # Final summary
    print(f"\n📊 Processing Summary:")
    print(f"   Processed {total_chunks_processed}/{len(date_chunks)} dates")
    print(f"   Total deposit records written: {total_records_processed}")
    if last_processed_id:
        print(f"   Last processed record ID: {last_processed_id}")
        print(f"   To continue from where you left off, use: --LastId {last_processed_id}")
    
    if is_first_chunk_written:
        print(f"✅ Output file completed: {csv_filepath}")
    else:
        print("❌ No data was written to output file.")
        
    if shutdown_requested:
        print("⚠️  Processing was interrupted but output file contains all data processed so far.")
        return  # Exit gracefully without error


if __name__ == "__main__":
    main()


