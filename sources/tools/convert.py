import yaml
import json
import sys

with open(sys.argv[1], 'r') as file:
    configuration = yaml.safe_load(file)

n_file = sys.argv[1].split(".")[0]
n_file = n_file + ".json"

with open(n_file, 'w') as json_file:
    json.dump(configuration, json_file, indent=4)

