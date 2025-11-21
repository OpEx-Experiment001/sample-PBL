
# Read the JSON data to convert to YAML for app_subagent
import json
import yaml

with open('healqueue_data.json', 'r') as f:
    data = json.load(f)

# Convert to YAML
yaml_data = yaml.dump(data, default_flow_style=False, sort_keys=False)

# Save YAML version
with open('healqueue_data.yaml', 'w') as f:
    f.write(yaml_data)

print("YAML data created for app generation")
print("\nFirst 500 characters of YAML:")
print(yaml_data[:500])
