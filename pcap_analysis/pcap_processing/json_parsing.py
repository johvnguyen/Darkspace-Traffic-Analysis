import json

def parse_json(json_fpath):
    with open(json_fpath, 'r') as file:
        data = json.load(file)

        return data

def getIsZMAP(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    return metadata['IsZmap']

def getIsMasscan(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    return metadata['IsMasscan']

def getIsMirai(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    return metadata['IsMirai']

def getIsBogon(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    return metadata['IsBogon']

def getKnownScanner(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    return metadata['KnownScanner']

def getKnownScannerEnum(ks):
    known_scanner_map = {
        '' : 0,
        'internet-census' : 1,
        'censys-io' : 2,
        'rapid7' : 3,
        'shodan-io' : 4,
        'shadowserver.org' : 5,
        'stretchoid.com' : 6,
        'internet-measurement-com' : 7
    }

    return known_scanner_map[ks]

def getASN(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    asn = metadata['SrcASN'].strip()
    if not asn:
        return 0

    return asn

def getNetacqCountry(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    return metadata['NetacqCountry']

def getMaxmindCountry(timeslice_metadata_pairs):
    _, metadata = timeslice_metadata_pairs[0]

    return metadata['MaxmindCountry']

def get_label(timeslice_metadata_pairs):
    metadata = [md for (ts, md) in timeslice_metadata_pairs]
    #print(metadata)
    zmaps = sum([1 if md['IsZmap'] else 0 for md in metadata ])
    masscans = sum([1 if md['IsMasscan'] else 0 for md in metadata ])
    mirais = sum([1 if md['IsMirai'] else 0 for md in metadata ])
    bogons = sum([1 if md['IsBogon'] else 0 for md in metadata ])
    is_known_scanner = [True if md['KnownScanner'] != '' else False for md in metadata ]

    labels = [zmaps, masscans, mirais, bogons]
    max_idx = labels.index(max(labels))

    if labels[max_idx] == 0:
        if any(is_known_scanner):
            return 5
        return 0

    if max_idx == 0:
        # ZMAP
        return 1
    elif max_idx == 1:
        # masscan
        return 2
    elif max_idx == 2:
        # mirai
        return 3
    elif max_idx == 3:
        # bogons
        return 4
    else:
        return 0
