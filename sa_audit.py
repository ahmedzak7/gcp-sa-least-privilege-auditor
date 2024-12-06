import google.auth
from google.cloud import logging
from googleapiclient.discovery import build
from datetime import datetime
import os

def parse_log_entry(entry, service_account_email):
    """
    Parse a log entry and extract key information.
    
    Args:
        entry: A Cloud Logging log entry
        service_account_email: Email of the service account
    
    Returns:
        dict: Parsed log entry details
    """
    try:
        # Extract basic log information
        timestamp = entry.timestamp.isoformat() if entry.timestamp else 'N/A'
        service_name = entry.payload.get('serviceName', 'N/A')
        method_name = entry.payload.get('methodName', 'N/A')
        
        # Extract authorization information
        auth_info = entry.payload.get('authorizationInfo', [{}])[0]
        permission = auth_info.get('permission', 'N/A')
        is_granted = str(auth_info.get('granted', False))
        
        # Extract request metadata
        request_metadata = entry.payload.get('requestMetadata', {})
        caller_ip = request_metadata.get('callerIp', 'N/A')
        request_time = request_metadata.get('requestAttributes', {}).get('time', 'N/A')
        
        # Extract resource details
        resource_name = entry.payload.get('resourceName', 'N/A')
        
        return {
            'Service Account': service_account_email,
            'Timestamp': timestamp,
            'Service': service_name,
            'Method': method_name,
            'Permission': permission,
            'Granted': is_granted,
            'Caller IP': caller_ip,
            'Request Time': request_time,
            'Resource': resource_name
        }
    except Exception as e:
        print(f"Error parsing log entry: {e}")
        return None

def get_service_account_logs(project_id, start_date, end_date):
    """
    Retrieve and process logs for service accounts in a project.
    
    Args:
        project_id (str): Google Cloud project ID
        start_date (str): Start date for log filtering
        end_date (str): End date for log filtering
    
    Returns:
        list: Processed logs for service accounts
    """
    # Authenticate using Application Default Credentials
    credentials, _ = google.auth.default()
    
    # Create a logging client for the project
    logging_client = logging.Client(credentials=credentials, project=project_id)
    
    # Build the IAM API client
    iam_service = build('iam', 'v1', credentials=credentials)
    
    # Get the list of service accounts in the project
    service_accounts = iam_service.projects().serviceAccounts().list(name=f'projects/{project_id}').execute()
    
    # Initialize a list to store processed logs
    all_processed_logs = []
    
    # Loop through each service account and fetch logs
    for service_account in service_accounts.get('accounts', []):
        email = service_account['email']
        print(f"Fetching logs for service account: {email}")
        
        # Construct the filter to query audit logs for this service account
        filter_str = (
            f'protoPayload.authenticationInfo.principalEmail="{email}" '
            f'timestamp>="{start_date}" timestamp<="{end_date}"'
        )
        
        # Fetch the logs using Cloud Logging API
        entries = logging_client.list_entries(filter_=filter_str)
        
        # Process and collect logs for this service account
        processed_logs = []
        for entry in entries:
            parsed_entry = parse_log_entry(entry, email)
            if parsed_entry:
                processed_logs.append(parsed_entry)
        
        # Add logs for this service account if any exist
        if processed_logs:
            all_processed_logs.extend(processed_logs)
    
    return all_processed_logs

def export_logs_to_csv(logs, output_filename='service_account_logs.csv'):
    """
    Export logs to a CSV file using basic file writing.
    
    Args:
        logs (list): List of processed log entries
        output_filename (str): Name of the output CSV file
    """
    if not logs:
        print("No logs to export.")
        return
    
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_filename) or '.', exist_ok=True)
    
    # Write logs to CSV
    try:
        # Get the column headers from the first log entry
        headers = list(logs[0].keys())
        
        # Write to file
        with open(output_filename, 'w', encoding='utf-8') as csvfile:
            # Write headers
            csvfile.write(','.join(headers) + '\n')
            
            # Write log entries
            for log in logs:
                # Convert each value to string and handle potential commas
                row = [str(log.get(header, '')).replace(',', ';') for header in headers]
                csvfile.write(','.join(row) + '\n')
        
        print(f"\nLogs exported successfully to {output_filename}")
        
        # Print first few lines of the CSV for verification
        print("\nFirst few lines of the exported CSV:")
        with open(output_filename, 'r', encoding='utf-8') as csvfile:
            for _ in range(5):  # Print first 5 lines
                print(csvfile.readline().strip())
    
    except Exception as e:
        print(f"Error exporting logs to CSV: {e}")

def validate_date(date_str):
    """
    Validate user-input date string.
    
    Args:
        date_str (str): Date string to validate
    
    Returns:
        str: Validated ISO format date string
    """
    try:
        # Try parsing the date in various common formats
        date_formats = [
            '%Y-%m-%d',           # YYYY-MM-DD
            '%Y-%m-%dT%H:%M:%SZ',  # YYYY-MM-DDTHH:MM:SSZ
            '%m/%d/%Y',            # MM/DD/YYYY
            '%d/%m/%Y'             # DD/MM/YYYY
        ]
        
        for date_format in date_formats:
            try:
                parsed_date = datetime.strptime(date_str, date_format)
                return parsed_date.strftime('%Y-%m-%dT%H:%M:%SZ')
            except ValueError:
                continue
        
        raise ValueError("Invalid date format")
    
    except Exception as e:
        print(f"Error parsing date: {e}")
        print("Please use formats like: YYYY-MM-DD, YYYY-MM-DDTHH:MM:SSZ, MM/DD/YYYY")
        return None

def main():
    # Ask the user to enter the project ID
    project_id = input("Enter your Google Cloud Project ID: ")

    # Prompt for start date with validation
    while True:
        start_date_input = input("Enter start date for log filtering (e.g., YYYY-MM-DD): ")
        start_date = validate_date(start_date_input)
        if start_date:
            break

    # Prompt for end date with validation
    while True:
        end_date_input = input("Enter end date for log filtering (e.g., YYYY-MM-DD): ")
        end_date = validate_date(end_date_input)
        if end_date:
            break

    # Get the processed logs
    logs = get_service_account_logs(project_id, start_date, end_date)

    if not logs:
        print("No logs found for any service accounts.")
    else:
        # Export logs to CSV
        export_logs_to_csv(logs)

if __name__ == "__main__":
    main()
