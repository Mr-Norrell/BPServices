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

def parse_xml_to_csv(xml_output, csv_filename):
    """Parses the SOAP XML response and writes data to a CSV file."""
    if not xml_output:
        print("No XML output to parse.")
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
    parser = argparse.ArgumentParser(description="Call Bank Mellat Transaction API and convert output to CSV.")
    parser.add_argument(
        "-U", "--Username",
        default="Sarmaye1402",
        help="Username for authentication (default: USERNAME)"
    )
    parser.add_argument(
        "-P", "--Password",
        default="18316913",
        help="Password for authentication (default: PASSWORD)"
    )
    parser.add_argument("-T", "--TerminalId", required=True, help="Terminal ID")
    parser.add_argument(
        "-F", "--FromDate",
        # No 'required=True', no 'default' here as it depends on ToDate
        help="From Date in YYYYMMDD format (defaults to ToDate if not provided)"
    )
    parser.add_argument("-O", "--ToDate", required=True, help="To Date in YYYYMMDD format")

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

    if args.Username == "USERNAME" or args.Password == "PASSWORD":
        print("Warning: Using default Username or Password. Please provide actual credentials for real use.")

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
        csv_filename = f"{args.TerminalId}-{args.FromDate}-{args.ToDate}.csv"
        script_dir = os.path.dirname(os.path.abspath(__file__))
        csv_filepath = os.path.join(script_dir, csv_filename)

        parse_xml_to_csv(xml_response, csv_filepath)
    else:
        print("Failed to get a response from the API.")

if __name__ == "__main__":
    main()
