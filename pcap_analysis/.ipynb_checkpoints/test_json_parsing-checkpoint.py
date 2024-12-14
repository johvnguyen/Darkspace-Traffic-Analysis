from pcap_processing.json_parsing import *
import pprint
from os import listdir


json_dir = 'telescopesampleanon/metadata/'
# Iterate through the list, loading each file for processing.
files = listdir("./telescopesampleanon/metadata")
#files = files[:2]

#jdata = parse_json(f'{json_dir}{files[0]}')
#print(jdata[0])

fpaths = [f'{json_dir}{file}' for file in files]

json_data = [parse_json(fpath) for fpath in fpaths]
json_data = [item for sublist in json_data for item in sublist]
#pprint.pprint(json_data)
#pprint.pprint(json_data[0][:])
known_scaner_values = set([data['KnownScanner'] for data in json_data])

print(f'KnownScanner values: {known_scaner_values}')
