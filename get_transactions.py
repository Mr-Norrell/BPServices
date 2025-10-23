#!/usr/bin/env python3

import argparse
import subprocess
import xml.etree.ElementTree as ET
import csv
import os
import uuid
import base64
from datetime import datetime, timedelta, timezone
import html
import json
import itertools
import time
import random
import tempfile
import shutil
# import shlex # For debugging curl command construction

def generate_soap_headers_values():
    """Generates dynamic values for SOAP headers."""
    now_utc = datetime.now(timezone.utc)
    expires_utc = now_utc + timedelta(minutes=5)

    # Format: YYYY-MM-DDTHH:MM:SS.mmmZ
    created_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    expires_str = expires_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # Generate a random nonce (16 bytes is common)
    nonce_bytes = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode('utf-8')

    # Generate unique IDs
    timestamp_id = f"TS-{uuid.uuid4().hex.upper()}"
    username_token_id = f"UsernameToken-{uuid.uuid4().hex.upper()}"

    return {
        "timestamp_id": timestamp_id,
        "created_timestamp": created_str,
        "expires_timestamp": expires_str,
        "username_token_id": username_token_id,
        "nonce": nonce_b64,
        "username_token_created": created_str # Usually same as timestamp created
    }

def build_soap_request(username, password, terminal_id, from_date, to_date, header_values):
    """Builds the SOAP XML request string."""
    return f"""<soap:Envelope xmlns:bpm="http://bpmellat.co/" xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
     <soap:Header>
        <wsse:Security soap:mustUnderstand="true" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
           <wsu:Timestamp wsu:Id="{header_values['timestamp_id']}">
              <wsu:Created>{header_values['created_timestamp']}</wsu:Created>
              <wsu:Expires>{header_values['expires_timestamp']}</wsu:Expires>
           </wsu:Timestamp>
           <wsse:UsernameToken wsu:Id="{header_values['username_token_id']}">
              <wsse:Username>{username}</wsse:Username>
              <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{password}</wsse:Password>
              <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{header_values['nonce']}</wsse:Nonce>
              <wsu:Created>{header_values['username_token_created']}</wsu:Created>
           </wsse:UsernameToken>
        </wsse:Security>
     </soap:Header>
     <soap:Body>
        <bpm:getTransactionByDate>
           <bpm:TerminalId>{terminal_id}</bpm:TerminalId>
           <bpm:FromDate>{from_date}</bpm:FromDate>
           <bpm:ToDate>{to_date}</bpm:ToDate>
        </bpm:getTransactionByDate>
     </soap:Body>
  </soap:Envelope>"""

def call_curl(soap_request_data):
    """Calls the curl command and returns the output."""
    url = "http://bos.bpm.bankmellat.ir/backoffice/Services/bpm/TransactionService.asmx?wsdl"
    headers = {
        "Content-Type": "text/xml;charset=utf-8"
    }

    curl_command = [
        'curl', '-X', 'POST', url,
        '-H', f"Content-Type: {headers['Content-Type']}",
        '-d', soap_request_data
    ]

    print("Executing curl command...")
    # To print the command for debugging:
    # print(" ".join(shlex.quote(c) for c in curl_command))
    try:
        process = subprocess.run(curl_command, capture_output=True, text=True, check=True, encoding='utf-8')
        print("Curl command executed successfully.")
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error during curl execution: {e}")
        print(f"Stderr: {e.stderr}")
        print(f"Stdout: {e.stdout}")
        return None
    except FileNotFoundError:
        print("Error: curl command not found. Please ensure curl is installed and in your PATH.")
        return None

def call_rest_curl(url, username, password, terminal_id, from_date, to_date, last_id=None, extra_headers=None):
    """
    Calls the REST endpoint via curl and returns the output (JSON string).
    
    Returns:
        str: The response body on success
        str: Error message with "ERROR:" prefix for permanent errors
        None: For transient errors that should be retried
    """
    if not url:
        print("Error: REST URL is required when using REST ApiType.")
        return "ERROR: Missing REST URL"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if isinstance(extra_headers, dict):
        headers.update(extra_headers)

    body = {
        "username": username,
        "password": password,
        "terminalId": terminal_id,
        "fromDate": from_date,
        "toDate": to_date
    }
    
    # Add id parameter for pagination if provided
    if last_id:
        body["id"] = last_id
        print(f"Using pagination: Requesting transactions after ID {last_id}")

    curl_command = [
        'curl',
        '--silent',            # do not print progress meter
        '--show-error',        # still show errors
        '--location',          # follow redirects
        '--connect-timeout', '30',  # timeout for connection phase
        '--max-time', '120',        # max time for the whole operation
        '-X', 'POST', url,
        '-H', f"Content-Type: {headers['Content-Type']}",
        '-H', f"Accept: {headers['Accept']}",
        '-u', f"{username}:{password}",
        '-d', json.dumps(body),
        '-w', '\nHTTP_STATUS:%{http_code}\nCONTENT_TYPE:%{content_type}\n'  # append status meta
    ]

    print("Executing REST curl command...")
    try:
        process = subprocess.run(curl_command, capture_output=True, text=True, check=False, encoding='utf-8')
        stdout_text = process.stdout or ""
        stderr_text = process.stderr or ""

        # Extract and log status meta if present (written to stdout due to -w)
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

        # Check for curl exit code first
        if process.returncode != 0:
            # Categorize the error based on curl exit codes and stderr
            curl_exit_code = process.returncode
            
            # Common curl exit codes for transient errors
            transient_curl_errors = {
                7: "Failed to connect",
                28: "Operation timeout",
                35: "SSL connect error",
                52: "Empty reply from server",
                56: "Failure in receiving network data",
                60: "Peer certificate cannot be authenticated"
            }
            
            # Permanent errors that shouldn't be retried
            permanent_curl_errors = {
                1: "Unsupported protocol",
                3: "URL malformed",
                5: "Couldn't resolve proxy",
                6: "Couldn't resolve host",
                22: "HTTP page not retrieved (404, etc)",
                51: "SSL peer certificate or SSH remote key was not OK",
                67: "Login denied"
            }
            
            if curl_exit_code in transient_curl_errors:
                error_desc = transient_curl_errors[curl_exit_code]
                print(f"Transient error: curl({curl_exit_code}) - {error_desc}")
                # Return None for transient errors to trigger retry
                return None
            elif curl_exit_code in permanent_curl_errors:
                error_desc = permanent_curl_errors[curl_exit_code]
                print(f"Permanent error: curl({curl_exit_code}) - {error_desc}")
                return f"ERROR: curl({curl_exit_code}) - {error_desc}"
            else:
                # For unknown exit codes, check stderr for common transient error patterns
                transient_patterns = [
                    "unexpected eof while reading",
                    "connection reset by peer",
                    "timeout",
                    "connection refused",
                    "network unreachable",
                    "ssl handshake failure"
                ]
                
                if stderr_text and any(pattern in stderr_text.lower() for pattern in transient_patterns):
                    print(f"Transient network error: {stderr_text.strip()}")
                    return None
                else:
                    print(f"Unknown curl error ({curl_exit_code}): {stderr_text.strip()}")
                    # For unknown errors, include the stderr in the response to help with debugging
                    return f"ERROR: curl({curl_exit_code}) - {stderr_text.strip()}"
        
        # Process successful responses
        if http_status is not None:
            print(f"REST status: {http_status} ({content_type or 'unknown content-type'})")
            
            # Handle HTTP status codes
            if http_status >= 200 and http_status < 300:
                # Success
                print("REST curl command executed successfully.")
                # Add HTTP status to the response for retry detection
                stdout_text += f"\nHTTP_STATUS:{http_status}"
            elif http_status == 429:
                # Rate limiting - should be retried
                print("Rate limit exceeded.")
                stdout_text += f"\nHTTP_STATUS:{http_status}"
            elif http_status >= 500:
                # Server errors - should be retried
                print(f"Server error: HTTP {http_status}")
                return None
            elif http_status >= 400 and http_status < 500:
                # Client errors - should not be retried
                print(f"Client error: HTTP {http_status}")
                return f"ERROR: HTTP {http_status} - Client error"
            else:
                # Other status codes
                stdout_text += f"\nHTTP_STATUS:{http_status}"
        else:
            print("REST curl command completed but no HTTP status was returned.")

        # If the server wrote body to stderr for some reason and stdout is empty, return stderr
        if not stdout_text.strip() and stderr_text.strip():
            print("Note: Empty stdout; using stderr as response body.")
            return stderr_text

        # Check for empty or invalid JSON response
        if not stdout_text.strip():
            print("Warning: Empty response body.")
            return None
            
        # Try to parse as JSON to validate the response
        try:
            json.loads(stdout_text)
        except json.JSONDecodeError:
            print("Warning: Response is not valid JSON. This might indicate a partial or corrupted response.")
            # If response is not valid JSON, treat as transient error
            if len(stdout_text) < 100:  # If it's a short response, print it for debugging
                print(f"Invalid JSON response: {stdout_text}")
            return None

        return stdout_text
        
    except FileNotFoundError:
        print("Error: curl command not found. Please ensure curl is installed and in your PATH.")
        return "ERROR: curl command not found"
    except Exception as e:
        print(f"Unexpected error during REST curl execution: {str(e)}")
        return None

def parse_xml_to_csv(xml_output, csv_filename):
    """Parses the SOAP XML response and writes data to a CSV file."""
    if not xml_output:
        print("No XML output to parse.")
        return False

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

def retry_with_backoff(func, *args, max_retries=3, initial_delay=2, backoff_factor=2, error_type="Unknown error", **kwargs):
    """
    Execute a function with retry logic and exponential backoff.
    
    Args:
        func: The function to execute
        *args: Positional arguments to pass to the function
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds
        backoff_factor: Factor by which the delay increases after each failure
        error_type: Description of the error being retried (for better logging)
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        The result of the function call, or None if all retries failed
    """
    delay = initial_delay
    result = None
    
    for attempt in range(max_retries + 1):
        if attempt > 0:
            # Add some jitter to the delay to prevent synchronized retries
            jitter = random.uniform(0.8, 1.2)
            actual_delay = delay * jitter
            
            print(f"{error_type}. Retrying in {actual_delay:.1f} seconds (attempt {attempt}/{max_retries})...")
            time.sleep(actual_delay)
            
            # Increase delay for next attempt
            delay *= backoff_factor
        
        try:
            result = func(*args, **kwargs)
            
            # Check if we got a rate limit response (HTTP 429)
            if isinstance(result, str) and "HTTP_STATUS:429" in result:
                error_type = "Rate limit exceeded"
                continue  # Retry
                
            # Check for empty response that might indicate a transient error
            if result is None or (isinstance(result, str) and not result.strip()):
                error_type = "Empty response received"
                continue  # Retry
                
            # Check for specific error strings that indicate transient issues
            transient_errors = [
                "unexpected eof while reading",
                "connection reset by peer",
                "timeout",
                "connection refused",
                "network unreachable",
                "ssl handshake failure"
            ]
            
            if isinstance(result, str) and any(error in result.lower() for error in transient_errors):
                error_type = "Transient network error"
                continue  # Retry
            
            # If we got here, the call was successful or failed for a reason other than the ones we're handling
            return result
            
        except Exception as e:
            error_type = f"Exception: {str(e)}"
            result = None
            continue  # Retry after exception
    
    # If we exhausted all retries
    print(f"Failed after {max_retries} retries due to: {error_type}")
    return result

def split_date_range(from_date_str, to_date_str, max_days=7):
    """Split a date range into chunks of max_days or less."""
    from_date = parse_date(from_date_str)
    to_date = parse_date(to_date_str)
    
    if not from_date or not to_date:
        return []
    
    if from_date > to_date:
        print(f"Error: FromDate {from_date_str} is after ToDate {to_date_str}")
        return []
    
    # Calculate total days in the range
    total_days = (to_date - from_date).days + 1
    
    if total_days <= max_days:
        # If within limit, return the original range
        return [(from_date_str, to_date_str)]
    
    # Split into chunks
    chunks = []
    current_from = from_date
    
    while current_from <= to_date:
        # Calculate the end of this chunk (either max_days away or to_date, whichever is sooner)
        current_to = min(current_from + timedelta(days=max_days-1), to_date)
        chunks.append((format_date(current_from), format_date(current_to)))
        current_from = current_to + timedelta(days=1)
    
    return chunks

def merge_json_responses(json_outputs):
    """Merges multiple JSON responses into a single data structure."""
    if not json_outputs:
        return None
    
    merged_data = None
    transaction_lists = []
    
    for json_output in json_outputs:
        if not json_output:
            continue
            
        try:
            parsed = json.loads(json_output)
            
            # Initialize merged_data with the first response structure
            if merged_data is None:
                merged_data = parsed.copy()
                if 'transactionInfoList' in merged_data:
                    # Store the transaction list separately and create an empty list in merged_data
                    transaction_lists.append(merged_data.get('transactionInfoList', []))
                    merged_data['transactionInfoList'] = []
            
            # For subsequent responses, just collect their transaction lists
            elif isinstance(parsed, dict) and 'transactionInfoList' in parsed:
                transaction_lists.append(parsed.get('transactionInfoList', []))
                
        except json.JSONDecodeError as e:
            print(f"Error parsing one of the JSON responses: {e}")
            continue
    
    # Merge all transaction lists into one
    if merged_data and 'transactionInfoList' in merged_data:
        merged_data['transactionInfoList'] = list(itertools.chain.from_iterable(transaction_lists))
    
    return merged_data

def merge_json_responses_with_temp_files(json_outputs_or_files, csv_filepath, is_files=False):
    """
    Merges multiple JSON responses using temp files to reduce memory usage.
    Writes directly to the final CSV file to minimize memory footprint.
    
    Args:
        json_outputs_or_files: List of JSON strings or file paths
        csv_filepath: Path to the final CSV output file
        is_files: If True, treats input as file paths; if False, as JSON strings
        
    Returns:
        dict: Processing statistics including success status, total transactions, and last ID
    """
    if not json_outputs_or_files:
        return {'success': False, 'error': 'No input data provided'}
    
    print(f"Processing {len(json_outputs_or_files)} responses with memory-optimized approach...")
    
    final_header = None
    final_csv = None
    writer = None
    
    total_transactions = 0
    last_transaction_id = None
    id_field = None
    success_status = None
    response_code = None
    response_message = None
    
    try:
        # Open the final CSV file for writing
        final_csv = open(csv_filepath, 'w', newline='', encoding='utf-8')
        
        for idx, json_data in enumerate(json_outputs_or_files):
            try:
                # Load the JSON data - either from string or from file
                if is_files:
                    with open(json_data, 'r', encoding='utf-8') as f:
                        parsed = json.load(f)
                else:
                    parsed = json.loads(json_data)
                
                # Extract status information from the first response
                if idx == 0:
                    success_status = parsed.get('success')
                    response_code = parsed.get('responseCode')
                    response_message = parsed.get('responseMessage')
                
                # Extract the transaction list
                records = parsed.get('transactionInfoList', [])
                if not records:
                    print(f"Chunk {idx+1}: No transactions found")
                    continue
                    
                # Get the header from the first chunk with data
                if final_header is None and records:
                    final_header = list(records[0].keys())
                    writer = csv.DictWriter(final_csv, fieldnames=final_header)
                    writer.writeheader()
                
                # Find ID field if not already found
                if not id_field and records:
                    id_field = next((field for field in ['Id', 'id', 'transactionId', 'transactionID', 'transaction_id'] 
                                   if field in records[-1]), None)
                
                # Write records directly to the final CSV
                chunk_count = 0
                for item in records:
                    if final_header:  # Only write if we have a header
                        row = {h: (item.get(h, '') if h in item else '') for h in final_header}
                        writer.writerow(row)
                        chunk_count += 1
                        total_transactions += 1
                
                # Update last transaction ID
                if id_field and records:
                    last_transaction_id = records[-1].get(id_field)
                
                # Free up memory immediately
                del records
                del parsed
                
                print(f"Processed chunk {idx+1}: Added {chunk_count} transactions")
                
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON chunk {idx+1}: {e}")
                continue
            except Exception as e:
                print(f"Error processing chunk {idx+1}: {e}")
                continue
                
        # Print status information
        if success_status is not None:
            print(f"Success: {success_status}")
        if response_code is not None or response_message is not None:
            print(f"Status: Code='{response_code}', Message='{response_message}'")
        
        # Return processing statistics
        result = {
            'success': True,
            'total_transactions': total_transactions,
            'last_transaction_id': last_transaction_id,
            'csv_path': csv_filepath
        }
        
        if total_transactions > 0:
            print(f"Successfully converted JSON data to {csv_filepath}")
            print(f"Retrieved {total_transactions} transactions")
            if last_transaction_id:
                print(f"Last transaction ID: {last_transaction_id}")
                print(f"To paginate and get the next batch, use: --LastId {last_transaction_id}")
        else:
            print("No transactions were processed")
            result['success'] = False
            result['error'] = 'No transactions found in any response'
        
        return result
        
    except Exception as e:
        print(f"Error during memory-optimized processing: {e}")
        return {'success': False, 'error': str(e)}
        
    finally:
        # Close the CSV file if it was opened
        if final_csv:
            final_csv.close()

def parse_json_to_csv(json_output, csv_filename):
    """Parses a JSON response and writes transaction data to a CSV file."""
    if not json_output:
        print("No JSON output to parse.")
        return False

    try:
        parsed = json.loads(json_output)
        last_transaction_id = None

        if isinstance(parsed, dict):
            success = parsed.get('success')
            response_code = parsed.get('responseCode')
            response_message = parsed.get('responseMessage')
            if success is not None:
                print(f"Success: {success}")
            if response_code is not None or response_message is not None:
                print(f"Status: Code='{response_code}', Message='{response_message}'")

            records = parsed.get('transactionInfoList')
            if isinstance(records, list) and records:
                header = list(records[0].keys())
                
                # Find the last transaction ID for pagination
                id_field = next((field for field in ['Id', 'id', 'transactionId', 'transactionID', 'transaction_id'] 
                               if field in records[-1]), None)
                if id_field:
                    last_transaction_id = records[-1].get(id_field)
                    if last_transaction_id:
                        print(f"Last transaction ID: {last_transaction_id}")
                        print(f"To paginate and get the next batch, use: --LastId {last_transaction_id}")
                
                with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=header)
                    writer.writeheader()
                    for item in records:
                        row = {h: (item.get(h, '') if isinstance(item, dict) else '') for h in header}
                        writer.writerow(row)
                print(f"Successfully converted JSON data to {csv_filename}")
                
                # Report transaction count
                print(f"Retrieved {len(records)} transactions")
                if len(records) == 10000:
                    print("Note: You received exactly 10,000 transactions, which is the API limit.")
                    print("There may be more transactions available. Use the Last ID to paginate.")
                
                return True

            # Fallback: write the dict as a single row
            header = list(parsed.keys())
            with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header)
                writer.writeheader()
                writer.writerow({h: parsed.get(h, '') for h in header})
            print(f"Wrote single-row JSON dictionary to {csv_filename}")
            return True

        if isinstance(parsed, list) and parsed:
            header = list(parsed[0].keys()) if isinstance(parsed[0], dict) else ["value"]
            with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header)
                writer.writeheader()
                for item in parsed:
                    if isinstance(item, dict):
                        writer.writerow({h: item.get(h, '') for h in header})
                    else:
                        writer.writerow({"value": item})
            print(f"Successfully converted JSON array to {csv_filename}")
            return True

        print("JSON did not contain recognizable transaction data.")
        return False
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        print("Problematic JSON (first 1000 chars):", json_output[:1000])
        return False
    except Exception as e:
        print(f"An unexpected error occurred during JSON parsing or CSV writing: {e}")
        return False

    try:
        # Define namespaces to properly find elements
        namespaces = {
            'soap': 'http://www.w3.org/2003/05/soap-envelope',
            'bpm': 'http://bpmellat.co/'
        }

        # Parse the outer SOAP envelope
        soap_root = ET.fromstring(xml_output)

        # Find the getTransactionByDateResult element
        result_element = soap_root.find('.//bpm:getTransactionByDateResult', namespaces)
        if result_element is None or result_element.text is None:
            result_element_alt_ns = soap_root.find('.//{http://bpmellat.co/}getTransactionByDateResult')
            if result_element_alt_ns is None or result_element_alt_ns.text is None:
                result_element_no_ns = soap_root.find('.//getTransactionByDateResult')
                if result_element_no_ns is None or result_element_no_ns.text is None:
                    print("Error: Could not find 'getTransactionByDateResult' element in the SOAP response.")
                    print("Received XML snippet:", xml_output[:1000])
                    return False
                else:
                    result_element = result_element_no_ns
            else:
                 result_element = result_element_alt_ns

        inner_xml_escaped = result_element.text
        if not inner_xml_escaped.strip():
            print("Error: 'getTransactionByDateResult' element is empty.")
            return False

        inner_xml_str = html.unescape(inner_xml_escaped)
        response_root = ET.fromstring(inner_xml_str)

        records_data = []
        header = []
        first_data_record = True

        for record_elem in response_root.findall('.//record'):
            current_record = {}
            is_status_record = False
            temp_header = []

            for field_elem in record_elem.findall('.//field'):
                field_name = field_elem.get('name')
                field_value = field_elem.get('value')
                current_record[field_name] = field_value
                temp_header.append(field_name)
                if field_name in ["responseCode", "responseDescription"]:
                    is_status_record = True

            if is_status_record:
                print(f"Status: Code='{current_record.get('responseCode')}', Description='{current_record.get('responseDescription')}'")
                if current_record.get('responseCode') != "000" and current_record.get('responseCode') is not None:
                    print(f"Warning: Response code is not '000'.")
                if len(response_root.findall('.//record')) == 1: # Only status record exists
                     records_data.append(current_record)
                     if first_data_record: # if it's also the first record overall
                        header = temp_header
                        first_data_record = False
                continue # Don't add status record to CSV data unless it's the only record

            # For actual data records
            if first_data_record:
                header = temp_header # Get headers from the first data record
                first_data_record = False
            records_data.append(current_record)

        if not records_data:
            print("No data records found to write to CSV.")
            if not response_root.findall('.//record'): # No records at all
                 print("The inner XML seems to contain no <record> elements.")
            return False
        if not header and records_data: # if only status record was processed and made it to records_data
             header = list(records_data[0].keys())


        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            writer.writeheader()
            for row_data in records_data:
                # Ensure all headers are present in row_data, fill with empty string if not
                row_to_write = {h: row_data.get(h, '') for h in header}
                writer.writerow(row_to_write)
        print(f"Successfully converted XML data to {csv_filename}")
        return True

    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        if 'inner_xml_str' in locals():
            print("Problematic inner XML (first 1000 chars):", inner_xml_str[:1000])
        elif 'xml_output' in locals():
            print("Problematic outer XML (first 1000 chars):", xml_output[:1000])
        return False
    except Exception as e:
        print(f"An unexpected error occurred during XML parsing or CSV writing: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Call Bank Mellat Transaction API and convert output to CSV.",
                                     epilog="For large datasets: Use --AutoPaginate to automatically fetch all transactions across multiple API calls.\n"
                                           "Memory management: Memory-optimized processing is used by default. Use --Fast for maximum speed if you have sufficient RAM.\n"
                                           "Error handling options: --MaxRetries controls retries for transient errors, --MaxConsecutiveFailures sets the limit for pagination failures.")
    parser.add_argument(
        "-U", "--Username",
        default="RSarmaye1402",
        help="Username for authentication (default: Sarmaye1402)"
    )
    parser.add_argument(
        "-P", "--Password",
        default="12021453",
        help="Password for authentication (default: 18316913)"
    )
    parser.add_argument(
        "-I", "--LastId",
        help="Last transaction ID for pagination (get transactions after this ID)"
    )
    parser.add_argument(
        "--AutoPaginate", 
        action="store_true",
        help="Automatically paginate through all results using the lastId"
    )
    parser.add_argument(
        "--MaxPages", 
        type=int, 
        default=10,
        help="Maximum number of pages to fetch when using AutoPaginate (default: 10)"
    )
    parser.add_argument("-T", "--TerminalId", required=True, help="Terminal ID")
    parser.add_argument(
        "-F", "--FromDate",
        # No 'required=True', no 'default' here as it depends on ToDate
        help="From Date in YYYYMMDD format (defaults to ToDate if not provided)"
    )
    parser.add_argument("-O", "--ToDate", required=True, help="To Date in YYYYMMDD format")
    parser.add_argument("--ApiType", choices=["soap", "rest"], default="rest", help="Choose API type: soap or rest (default: rest)")
    parser.add_argument("--RestUrl", default="https://bos.behpardakht.com/bhrws/transactionInfo/getTransactionByDate", help="REST endpoint URL (default: https://bos.behpardakht.com/bhrws/transactionInfo/getTransactionByDate)")
    parser.add_argument("--ChunkSize", type=int, default=7, help="Maximum number of days per API request chunk (default: 7)")
    parser.add_argument("--Delay", type=float, default=3, help="Delay in seconds between API requests to avoid rate limiting (default: 3)")
    parser.add_argument("--MaxRetries", type=int, default=3, help="Maximum number of retries for failed API requests (default: 3)")
    parser.add_argument("--MaxConsecutiveFailures", type=int, default=3, help="Maximum number of consecutive failures before giving up on pagination (default: 3)")
    parser.add_argument("--Fast", action="store_true", help="Use high-memory processing for maximum speed (loads all data into RAM simultaneously)")

    args = parser.parse_args()

    # Set FromDate to ToDate if FromDate is not provided
    if args.FromDate is None:
        args.FromDate = args.ToDate
        print(f"FromDate not provided, defaulting to ToDate: {args.FromDate}")


    # Date format validation
    # ToDate must always be valid as it's required
    if not (len(args.ToDate) == 8 and args.ToDate.isdigit()):
        print("Error: ToDate must be in YYYYMMDD format.")
        return
    # FromDate (which is now guaranteed to have a value) must also be valid
    if not (len(args.FromDate) == 8 and args.FromDate.isdigit()):
        # This case should ideally not be hit if FromDate defaults to a valid ToDate,
        # but good for explicit user input.
        print("Error: FromDate must be in YYYYMMDD format.")
        return


    # Include LastId in filename if provided for pagination
    if args.LastId:
        csv_filename = f"{args.TerminalId}-{args.FromDate}-{args.ToDate}-after-{args.LastId}.csv"
    else:
        csv_filename = f"{args.TerminalId}-{args.FromDate}-{args.ToDate}.csv"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_filepath = os.path.join(script_dir, csv_filename)

    if args.ApiType == "soap":
        header_values = generate_soap_headers_values()

        soap_request = build_soap_request(
            args.Username,
            args.Password,
            args.TerminalId,
            args.FromDate,
            args.ToDate,
            header_values
        )
        # print("Generated SOAP Request:\n", soap_request) # For debugging

        xml_response = call_curl(soap_request)
        if xml_response:
            parse_xml_to_csv(xml_response, csv_filepath)
        else:
            print("Failed to get a response from the SOAP API.")
    else:
        # For REST API, check if we need to split the date range according to the chunk size
        date_chunks = split_date_range(args.FromDate, args.ToDate, max_days=args.ChunkSize)
        
        if not date_chunks:
            print("Failed to process date range. Please check your date format.")
            return
            
        if len(date_chunks) > 1:
            print(f"Date range exceeds {args.ChunkSize} days. Breaking into {len(date_chunks)} chunks:")
            for i, (chunk_from, chunk_to) in enumerate(date_chunks):
                print(f"  Chunk {i+1}: {chunk_from} to {chunk_to}")
        
        # Use the delay specified in command line arguments
        delay_between_requests = args.Delay
        
        # Collect all responses from all chunks
        all_json_responses = []
        
        # Handle each date chunk
        for chunk_idx, (chunk_from, chunk_to) in enumerate(date_chunks):
            if chunk_idx > 0:
                print(f"\n--- Processing date chunk {chunk_idx+1}/{len(date_chunks)} ---")
            
            # For auto-pagination, we'll collect all responses for this date chunk
            chunk_json_responses = []
            current_last_id = args.LastId  # Start with user-provided LastId if any
            page_count = 0
            has_more_data = True
            
            # Loop for auto-pagination within this date chunk
            consecutive_failures = 0
            max_consecutive_failures = args.MaxConsecutiveFailures  # Use the command-line parameter
            last_successful_id = current_last_id  # Keep track of the last successful ID
            
            while has_more_data:
                page_count += 1
                
                # Break if we've reached the maximum number of pages
                if args.AutoPaginate and page_count > args.MaxPages:
                    print(f"Reached maximum number of pages ({args.MaxPages}). Stopping pagination.")
                    break
                
                # Add delay between requests to avoid rate limiting, except for the first request
                if page_count > 1 or chunk_idx > 0:
                    delay_with_jitter = delay_between_requests * random.uniform(0.9, 1.1)
                    print(f"Waiting {delay_with_jitter:.1f} seconds before next request...")
                    time.sleep(delay_with_jitter)
                
                if args.AutoPaginate and page_count > 1:
                    print(f"Auto-paginating: Requesting page {page_count} (transactions after ID: {current_last_id})")
                elif current_last_id:
                    print(f"Requesting data for period {chunk_from} to {chunk_to} (after ID: {current_last_id})")
                else:
                    print(f"Requesting data for period: {chunk_from} to {chunk_to}")
                
                # Use retry mechanism for the API call
                json_response = retry_with_backoff(
                    call_rest_curl,
                    args.RestUrl,
                    args.Username,
                    args.Password,
                    args.TerminalId,
                    chunk_from,
                    chunk_to,
                    current_last_id,  # Pass the current LastId parameter for pagination
                    max_retries=args.MaxRetries,
                    initial_delay=3,
                    backoff_factor=2,
                    error_type="API request failed"
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
                    
                    # Remove any HTTP status information we added for retry detection
                    if "\nHTTP_STATUS:" in json_response:
                        json_response = json_response.split("\nHTTP_STATUS:")[0]
                    
                    # Extract the last transaction ID for auto-pagination
                    last_id = None
                    if args.AutoPaginate:
                        try:
                            parsed = json.loads(json_response)
                            records = parsed.get('transactionInfoList', [])
                            
                            if not records:
                                print("No transactions in response. Ending pagination.")
                                has_more_data = False
                            elif len(records) < 10000:
                                print(f"Retrieved {len(records)} transactions (less than 10,000). End of data reached.")
                                has_more_data = False
                            else:
                                # Print available fields in the last record for debugging
                                print(f"Available fields in response: {list(records[-1].keys())}")
                                
                                # Find the last transaction ID for pagination
                                # Try common ID field names first
                                id_field = next((field for field in ['Id', 'id', 'transactionId', 'transactionID', 'transaction_id', 'TransactionId'] 
                                               if field in records[-1]), None)
                                
                                # If not found, look for any field containing 'id' or 'ID' in its name
                                if not id_field:
                                    id_field = next((field for field in records[-1].keys() 
                                                   if 'id' in field.lower()), None)
                                
                                if id_field:
                                    last_id = records[-1].get(id_field)
                                    if last_id:
                                        print(f"Retrieved 10,000 transactions. Using field '{id_field}' with last ID: {last_id}")
                                        current_last_id = last_id
                                        last_successful_id = last_id  # Update the last successful ID
                                    else:
                                        print(f"Field '{id_field}' exists but value is empty. Ending pagination.")
                                        has_more_data = False
                                else:
                                    print("No ID field found in response. Ending pagination.")
                                    has_more_data = False
                        except Exception as e:
                            print(f"Error extracting last ID: {e}")
                            # Don't stop pagination on JSON parsing error if we have a valid response
                            # Just use the previous last_id
                            if current_last_id:
                                print(f"Continuing with previous ID: {current_last_id}")
                            else:
                                has_more_data = False
                    else:
                        # If not auto-paginating, we're done after one request
                        has_more_data = False
                    
                    # Add this response to our collection
                    chunk_json_responses.append(json_response)
                    
                    # If not auto-paginating or we couldn't extract a last ID, we're done
                    if not args.AutoPaginate:
                        break
                else:
                    # Transient error or no response
                    consecutive_failures += 1
                    print(f"Request failed (attempt {consecutive_failures}/{max_consecutive_failures})")
                    
                    if consecutive_failures >= max_consecutive_failures:
                        print(f"Reached maximum consecutive failures ({max_consecutive_failures}). Stopping pagination for this chunk.")
                        
                        # If we had at least one successful response before, we can continue from the last successful ID
                        if last_successful_id and last_successful_id != args.LastId:
                            print(f"Will use last successful ID ({last_successful_id}) for the next chunk if available.")
                            current_last_id = last_successful_id
                        
                        has_more_data = False
                    else:
                        # For transient errors, add a longer delay before retrying
                        retry_delay = delay_between_requests * (consecutive_failures + 1) * random.uniform(1.0, 1.5)
                        print(f"Transient error occurred. Will retry in {retry_delay:.1f} seconds...")
                        time.sleep(retry_delay)
            
            # Add all responses from this chunk to our overall collection
            if chunk_json_responses:
                all_json_responses.extend(chunk_json_responses)
            else:
                print("Failed to get any valid responses from the REST API for this date chunk.")
                
        # Process all responses from all chunks into a single output file
        if all_json_responses:
            if args.Fast:
                # Use high-memory approach (traditional approach - keep all in memory)
                if len(all_json_responses) > 1:
                    print(f"Merging {len(all_json_responses)} responses into a single output file...")
                    merged_data = merge_json_responses(all_json_responses)
                    if merged_data:
                        # Convert merged data back to JSON string
                        merged_json = json.dumps(merged_data)
                        parse_json_to_csv(merged_json, csv_filepath)
                    else:
                        print("Failed to merge JSON responses.")
                else:
                    # Just one response, process it directly
                    parse_json_to_csv(all_json_responses[0], csv_filepath)
            else:
                # Use memory-optimized approach (default)
                result = merge_json_responses_with_temp_files(all_json_responses, csv_filepath)
                if not result.get('success'):
                    print(f"Failed to process responses with memory-optimized approach: {result.get('error', 'Unknown error')}")
        else:
            print("Failed to get any valid responses from the REST API.")

if __name__ == "__main__":
    main()
