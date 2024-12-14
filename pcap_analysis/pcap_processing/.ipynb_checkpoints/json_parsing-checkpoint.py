import json

def parse_json(json_fpath):
    with open(json_fpath, 'r') as file:
        data = json.load(file)

        return data

