import json
import subprocess
import pandas as pd
import time
from datetime import datetime, timedelta
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException

# Function to execute a shell command and return the output, including error message.
def run_command(command):
    try:
        process = subprocess.run(
            command, check=True, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True
        )
        return process.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

def run_command_json(command):
    output = run_command(command)
    return json.loads(output) if output else None

def get_pandas_dataframe(info_list):
    return pd.DataFrame(info_list, columns=['Category', 'Property', 'Value'])

def wait_for_pod_completion(api_instance, pod_name, namespace="default", timeout=300):
    w = watch.Watch()
    start_time = datetime.now()
    while (datetime.now() - start_time).total_seconds() < timeout:
        pod = api_instance.read_namespaced_pod(name=pod_name, namespace=namespace)
        if pod.status.phase == "Succeeded" or pod.status.phase == "Failed":
            return pod.status.phase == "Succeeded"
        time.sleep(5)  # Add a delay between checks to avoid hammering the API
    return False  # Timeout occurred

def check_internet_access(namespace="default"):
    config.load_kube_config()
    api_instance = client.CoreV1Api()

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
        api_response = api_instance.create_namespaced_pod(namespace=namespace, body=pod_manifest)
        print("Pod created. Status='%s'" % str(api_response.status))
    except ApiException as e:
        print("Exception when calling CoreV1Api->create_namespaced_pod: %s\n" % e)
        return False

    # Wait for pod to complete and get status
    success = wait_for_pod_completion(api_instance, "internet-test-pod", namespace)

    # Delete pod
    try:
        api_response = api_instance.delete_namespaced_pod(
            name="internet-test-pod", namespace=namespace,
            body=client.V1DeleteOptions()
        )
        print("Pod deleted. Status='%s'" % str(api_response.status))
    except ApiException as e:
        print("Exception when calling CoreV1Api->delete_namespaced_pod: %s\n" % e)

    return success

def detect_kubernetes_distribution():
    # Check for cloud providers
    node_labels = json.loads(run_command('kubectl get nodes -o json'))
    for node in node_labels['items']:
        labels = node['metadata']['labels']
        if 'cloud.google.com/gke-nodepool' in labels:
            return 'Google Kubernetes Engine (GKE)'
        if 'kubernetes.azure.com/cluster' in labels:
            return 'Azure Kubernetes Service (AKS)'
        if 'eks.amazonaws.com/nodegroup' in labels:
            return 'Amazon Elastic Kubernetes Service (EKS)'

    # Check for OpenShift
    openshift_version = run_command('oc version')
    if openshift_version and 'openshift' in openshift_version.lower():
        return 'Red Hat OpenShift'

    # Fallback to checking for other identifying features if needed

    # If none of the above checks work, return generic Kubernetes or an indication to check manually
    return 'Generic Kubernetes / Unknown (Manual check required)'

def format_kubernetes_version(version_info):
    client_version = version_info.get('clientVersion', {})
    client_str = f"Client: v{client_version.get('major', '')}.{client_version.get('minor', '')} {client_version.get('gitVersion', '')}"

    server_version = version_info.get('serverVersion', {})
    server_str = f"Server: v{server_version.get('major', '')}.{server_version.get('minor', '')} {server_version.get('gitVersion', '')}"

    return f"{client_str}, {server_str}"

# Collecting the information
info = []

# Environment Compatibility
kubernetes_version_info = run_command_json('kubectl version --output=json')
if kubernetes_version_info:
    formatted_kubernetes_version = format_kubernetes_version(kubernetes_version_info)
    info.append(('Environment Compatibility', 'Kubernetes Version', formatted_kubernetes_version))
else:
    info.append(('Environment Compatibility', 'Kubernetes Version', 'Error retrieving version'))


info.append(('Environment Compatibility', 'Helm Version', run_command('helm version --short')))
kubernetes_distribution = detect_kubernetes_distribution()
info.append(('Environment Compatibility', 'Kubernetes Distribution', kubernetes_distribution))
info.append(('Environment Compatibility', 'Container Runtime', run_command("kubectl get nodes -o=jsonpath='{.items[*].status.nodeInfo.containerRuntimeVersion}'")))
info.append(('Environment Compatibility', 'Node Operating System and Architecture', run_command("kubectl get nodes -o=jsonpath='{.items[*].status.nodeInfo.operatingSystem}/{.items[*].status.nodeInfo.architecture}'")))

# Resource Limits
resource_quotas = run_command("kubectl describe quota --all-namespaces")
info.append(('Resource Limits', 'Resource Quotas', resource_quotas))

# Pod Security Policies (PSP) check
psp_resources = run_command('kubectl api-resources | grep -w "podsecuritypolicies"')
if "Error:" not in psp_resources:
    psps_status = run_command('kubectl get psp')
    info.append(('Pod Security Policies (PSP)', 'PSP status', 'configured' if psps_status else 'not configured'))
    info.append(('Pod Security Policies (PSP)', 'PSPs in Place', psps_status if psps_status else 'None'))
else:
    info.append(('Pod Security Policies (PSP)', 'PSP status', 'not available in this cluster version'))

# Open Policy Agent (OPA) check
opa_status = run_command('kubectl get deploy -n opa')
info.append(('Open Policy Agent (OPA)', 'OPA status', 'in use' if opa_status else 'not in use'))
opa_policies = run_command('kubectl get cm -n opa -l openpolicyagent.org/policy=rego')
info.append(('Open Policy Agent (OPA)', 'OPA policies', opa_policies))

# Internet Access Check
internet_access_success = check_internet_access()  # The call to check internet access
if internet_access_success:
    internet_access = 'Internet access is available for pods.'
else:
    internet_access = 'Internet access is NOT available for pods. Check network policies, egress settings, and service configurations.'

info.append(('Internet Access', 'Direct Internet Access for Pods', internet_access))

# Storage
storage_classes = run_command('kubectl get sc -o=json')
info.append(('Storage', 'Available storage classes', storage_classes))

# Dynamic provisioning
dynamic_provisioning_status = run_command("kubectl get sc --no-headers | awk '$2 == \"(default)\"'")
is_dynamic_provisioning = 'Available' if dynamic_provisioning_status else 'Not Available'
info.append(('Storage', 'Dynamic Provisioning', is_dynamic_provisioning))

# Ingress/Egress
ingress_controllers = run_command('kubectl get pods -n ingress-nginx')
info.append(('Ingress/Egress', 'Ingress controller in use', ingress_controllers if ingress_controllers else 'None'))
info.append(('Ingress/Egress', 'Egress restrictions or firewall rules', "Manual check required"))

# Third-party Integrations and Image Repositories
info.append(('Third-party Integrations', 'Tools or platforms integrated with the cluster', "Manual check required"))
info.append(('Image Repositories', 'List all Image Repositories', "Manual check required"))

# Create DataFrame and save to Excel
df = get_pandas_dataframe(info)
df.to_excel("kubernetes_info.xlsx", index=False, engine='openpyxl')

print("Information has been written to kubernetes_info.xlsx")
