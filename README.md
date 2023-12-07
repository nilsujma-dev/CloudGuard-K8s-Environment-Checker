## Kubernetes Cluster Environment and Internet Access Checker

This GitHub repository contains a Python script for checking and documenting specific aspects of a Kubernetes cluster's environment and internet access capabilities. It provides a convenient way to verify the Kubernetes version and test pod internet access, with results documented in an Excel file.

### Script Functionality
1. **Kubernetes Version Check**: Retrieves the Kubernetes cluster's version information, including major, minor, and git versions.
2. **Internet Access Testing**:
   - Creates a temporary pod in the Kubernetes cluster to test direct internet access.
   - Uses the `busybox` image to execute a simple connectivity test (`wget` command) to `http://google.com`.
   - Monitors the pod's status to determine the success or failure of the internet connectivity test.
   - Cleans up by deleting the test pod after the check.
3. **Result Documentation**:
   - Compiles the Kubernetes version and internet access test results.
   - Writes the results to an Excel file (`kubernetes_info.xlsx`) for easy review and record-keeping.

### Key Features
- **Automated Kubernetes Checks**: Simplifies the process of checking the Kubernetes environment and pod internet access.
- **Logging and Error Handling**: Incorporates logging for each step and handles exceptions gracefully.
- **Excel Report Generation**: Outputs the findings in a well-structured Excel file, enhancing the readability and usability of the data.

### Usage Scenario
The script is ideal for Kubernetes administrators and DevOps engineers who need to routinely check their cluster's environment and internet access capabilities. It is particularly useful for initial environment verification, troubleshooting, and documentation purposes.

### Prerequisites
- A Python environment with the Kubernetes Python client (`kubernetes`) and `openpyxl` libraries.
- Access to a Kubernetes cluster with permissions to create and delete pods.

### Security and Best Practices
- Ensure appropriate cluster access controls and permissions are in place, as the script interacts with Kubernetes resources.
- Handle the generated Excel file securely, as it contains information about the cluster environment.

---

This readme summary offers a comprehensive overview of the script's functionality and its application in Kubernetes environment verification. It guides users through using the script to check critical aspects of their Kubernetes setup and document the findings effectively.
