import logging
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from openpyxl import Workbook

# Initialize Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the kube config
config.load_kube_config()
api_instance = client.CoreV1Api()

# Function to get Kubernetes version information
def get_kubernetes_version():
    version_info = client.VersionApi().get_code()
    return f"{version_info.major}.{version_info.minor} {version_info.git_version}"

# Function to create and delete pod for internet access check
def check_internet_access(namespace="default"):
    pod_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "internet-test-pod"
        },
        "spec": {
            "containers": [{
                "name": "busybox",
                "image": "busybox",
                "command": ["wget", "--spider", "http://google.com"]
            }],
            "restartPolicy": "Never"
        }
    }

    # Create pod
    try:
        api_instance.create_namespaced_pod(namespace=namespace, body=pod_manifest)
        logging.info("Pod internet-test-pod created.")
    except ApiException as e:
        logging.error(f"An exception occurred when creating pod: {e}")
        return False

    # Initialize watch for pod completion
    w = watch.Watch()
    try:
        for event in w.stream(api_instance.list_namespaced_pod, namespace=namespace, timeout_seconds=300):
            pod = event['object']
            if pod.metadata.name == "internet-test-pod" and pod.status.phase in ("Succeeded", "Failed"):
                w.stop()
                break
    except Exception as e:
        logging.error(f"An exception occurred when watching pod: {e}")
    finally:
        w.stop()
        # Attempt to delete pod
        try:
            api_instance.delete_namespaced_pod(name="internet-test-pod", namespace=namespace, body=client.V1DeleteOptions())
            logging.info("Pod internet-test-pod deleted.")
        except ApiException as e:
            logging.error(f"An exception occurred when deleting pod: {e}")

    # Check the pod's completion status
    try:
        pod_status = api_instance.read_namespaced_pod_status(name="internet-test-pod", namespace=namespace)
        return pod_status.status.phase == "Succeeded"
    except ApiException:
        logging.error("Failed to retrieve pod status for internet-test-pod.")
        return False

# Function to write results to an Excel file
def write_to_excel(info):
    wb = Workbook()
    ws = wb.active
    ws.append(['Category', 'Property', 'Value'])
    for item in info:
        ws.append(item)
    wb.save("kubernetes_info.xlsx")
    logging.info("Information has been written to kubernetes_info.xlsx")

if __name__ == "__main__":
    # Collect Kubernetes cluster information
    info = []
    info.append(('Environment Compatibility', 'Kubernetes Version', get_kubernetes_version()))
    internet_access_successful = check_internet_access()
    info.append(('Internet Access', 'Direct Internet Access for Pods', 'Yes' if internet_access_successful else 'No'))

    # Write the information to an Excel file
    write_to_excel(info)
