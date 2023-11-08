import json
import subprocess
import pandas as pd
import time
from datetime import datetime, timedelta
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException

# Function to execute a shell command and return the output, including the error message.
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

# Function to get a pandas DataFrame from a list of info
def get_pandas_dataframe(info_list):
    return pd.DataFrame(info_list, columns=['Category', 'Property', 'Value'])

# Function to wait for pod completion and return the result
def wait_for_pod_completion(api_instance, pod_name, namespace="default", timeout=300):
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

# Collecting the information
info = []

# Environment Compatibility
info.append(('Environment Compatibility', 'Kubernetes Version', run_command('kubectl version --output=json')))
info.append(('Environment Compatibility', 'Helm Version', run_command('helm version --short')))
info.append(('Environment Compatibility', 'Kubernetes Distribution', "Manual check required"))
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
storage_classes = run_command('kubectl get sc')
info.append(('Storage', 'Available storage classes and any restrictions', storage_classes))
dynamic_provisioning = run_command('kubectl get sc -o=jsonpath="{.items[?(@.provisioner!=\'kubernetes.io/no-provisioner\')].metadata.name}"')
info.append(('Storage', 'Dynamic provisioning status', dynamic_provisioning))

# Ingress/Egress
ingress_controllers = run_command('kubectl get ingresscontrollers -A')
info.append(('Ingress/Egress', 'Ingress controller in use', ingress_controllers))
info.append(('Ingress/Egress', 'Egress restrictions or firewall rules', "Manual check required"))

# Third-party Integrations and Image Repositories
# These would require knowledge of the specific cluster setup or applications in use.
info.append(('Third-party Integrations', 'Tools or platforms integrated with the cluster', "Manual check required"))
info.append(('Image Repositories to onboard', 'List all Image Repositories', "Manual check required"))

# Create DataFrame and save to Excel
df = get_pandas_dataframe(info)
df.to_excel("kubernetes_info.xlsx", index=False, engine='openpyxl')

print("Information has been written to kubernetes_info.xlsx")