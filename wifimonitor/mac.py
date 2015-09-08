import requests


def get_mac_vendor(mac):
    try:
        res = requests.get('http://macvendorlookup.com/api/v2/{}'.format(mac))
        data = res.json()
        vendor = data[0]['company'].split(None, 1)[0]
    except:
        return
    else:
        return vendor
