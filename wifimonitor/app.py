import argparse
import datetime
import redis
import yaml

from scapy.fields import EnumField
from scapy.layers.dot11 import Dot11Auth, Dot11ProbeReq, Dot11ProbeResp, sniff

from wifimonitor.tts import speak
from wifimonitor.mac import get_mac_vendor

redis_connection = redis.Redis()
config = {}

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-c', '--config',
                        help='Configuration file.')


def hasflag(pkt, field_name, value):
    field, val = pkt.getfield_and_val(field_name)
    if isinstance(field, EnumField):
        if val not in field.i2s:
            return False
        return field.i2s[val] == value
    else:
        return ((1 << field.names.index([value])) &
                getattr(pkt, field_name)) != 0


def get_station_bssid(pkt):
    if pkt.haslayer(Dot11ProbeReq) or hasflag(pkt, 'FCfield', 'to-DS'):
        return pkt.addr2
    else:
        return pkt.addr1


def PacketHandler(pkt):
    if any(pkt.haslayer(layer) for layer in (
            Dot11Auth, Dot11ProbeReq, Dot11ProbeResp)):
        bssid = get_station_bssid(pkt)
    else:
        return
    # 0 dB == 255
    strength = ord(pkt.notdecoded[-4])
    if strength >= config['threshold']:
        pipeline = redis_connection.pipeline()
        pipeline.incr(bssid)
        pipeline.expire(bssid, config['timeout'])
        result = pipeline.execute()
        count = result[0]
        if count == 5:
            if bssid in config['devices']:
                speak('{} found'.format(config['devices'][bssid]))
            else:
                speak('Unknown {} device found'.format(get_mac_vendor(bssid)))

    now = datetime.datetime.now()
    print('{} {} {}'.format(now, bssid, strength))


def main():
    args = arg_parser.parse_args()
    config_file = args.config
    if config_file:
        try:
            with open(config_file) as fp:
                config.update(yaml.load(fp.read()))
        except:
            # Cannot read configuration file
            pass

    speak('Starting scanner')
    sniff(iface=config['interface'], prn=PacketHandler,
          filter='type mgt and '
          '(subtype auth or subtype probe-req or subtype probe-resp)',
          store=False)

if __name__ == '__main__':
    main()
