# gcp-sa-least-privilege-auditor
# GCP Service Account Least Privilege Auditor

This script helps you nail down least privilege by precisely tracking the permissions actually used by GCP service accounts within a project.

## Features

- **Pulls audit logs** across all service accounts in a specified project.
- **Custom date range filtering** to narrow down analysis.
- **Extracts key details** such as permissions, timestamps, and caller IPs.
- **Exports to CSV** for easy analysis and reporting.

## Requirements

- **Python 3.x** installed.
- **Google Cloud SDK (`gcloud`)** installed and configured with the necessary permissions.

## Usage

1. **Clone the repository**:

    ```bash
    git clone https://github.com/yourusername/gcp-sa-least-privilege-auditor.git
    cd gcp-sa-least-privilege-auditor
    ```

2. **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

3. **Run the script**:

    ```bash
    python sa_audit.py
    ```

4. **Provide the required inputs** when prompted:

    - **Project ID**
    - **Start Date** (e.g., `2024-01-12T00:00:00Z`)
    - **End Date** (e.g., `2024-01-12T23:59:59Z`)

5. **Detailed CSV Export**:

    The script will generate a CSV file containing the following information:

    | Timestamp           | Service Account                    | Permission             | Caller IP       |
    |---------------------|------------------------------------|------------------------|----------------|
    | 2024-01-12T10:30Z  | my-sa@project.iam.gserviceaccount.com | storage.objects.list | 192.168.1.1    |

## Contributing

Pull requests and suggestions are welcome!

## License

Licensed under the MIT License.
