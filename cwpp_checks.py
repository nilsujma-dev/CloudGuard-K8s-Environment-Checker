import json
import subprocess
import pandas as pd

# Function to execute a shell command and return the output.
def run_command(command):
    try:
        process = subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return process.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return None

def run_command_json(command):
    output = run_command(command)
    return json.loads(output) if output else None

def get_pandas_dataframe(info_list):
    return pd.DataFrame(info_list, columns=['Category', 'Property', 'Value'])

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

# Pod Security Policies (PSP)
psps_status = run_command('kubectl get psp')
info.append(('Pod Security Policies (PSP)', 'PSP status', 'enabled' if psps_status else 'disabled'))
info.append(('Pod Security Policies (PSP)', 'PSPs in Place', psps_status))

# Open Policy Agent (OPA)
opa_status = run_command('kubectl get deploy -n opa')
info.append(('Open Policy Agent (OPA)', 'OPA status', 'in use' if opa_status else 'not in use'))
opa_policies = run_command('kubectl get cm -n opa -l openpolicyagent.org/policy=rego')
info.append(('Open Policy Agent (OPA)', 'OPA policies', opa_policies))

# Node Affinities & Tolerations
node_taints = run_command('kubectl get nodes -o=jsonpath="{.items[*].spec.taints}"')
info.append(('Node Affinities & Tolerations', 'Taints applied to nodes', node_taints))

# Annotations are specific to the cluster setup and require manual inspection for your workloads.
info.append(('Annotations', 'Mandatory annotations for workloads', 'Manual check required'))
info.append(('Annotations', 'Required annotations for network policies or security', 'Manual check required'))

# Service Accounts & RBAC
rbac_status = run_command('kubectl get clusterrolebinding')
info.append(('Service Accounts & RBAC', 'RBAC status', 'enforced' if 'cluster-admin' in rbac_status else 'not enforced'))

# Network Policies
network_policies = run_command('kubectl get networkpolicy --all-namespaces')
info.append(('Network Policies', 'Default deny network policies status', network_policies))
info.append(('Network Policies', 'Additional network policies required', "Manual check required"))

# Internet Access
internet_access = 'Manual check required (Check network policies, egress settings, and potentially service configurations)'
info.append(('Internet Access', 'Direct Internet Access for Pods', internet_access))

# Storage
storage_classes = run_command('kubectl get sc')
info.append(('Storage', 'Available storage classes and any restrictions', storage_classes))
dynamic_provisioning = run_command('kubectl get sc -o=jsonpath="{.items[?(@.provisioner!=\"kubernetes.io/no-provisioner\")].metadata.name}"')
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