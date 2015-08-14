import argparse
import datetime
import redis
import subprocess
import threading
import time

from scapy.fields import EnumField
from scapy.layers.dot11 import Dot11Auth, Dot11ProbeReq, Dot11ProbeResp
from scapy.all import sniff

from wifimonitor.tts import speak

redis_connection = redis.Redis()
config = {}

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-i', '--interface', default='mon0',
                        help='Interface to monitor.')
arg_parser.add_argument('-t', '--timeout', default=60*5,
                        help='Timeout.')
arg_parser.add_argument('--threshold', default=200,
                        help='Signal strength threshold. maximum is 255.')


def channel_hopper(interface):
    while 1:
        for channel in range(1, 13 + 1):
            subprocess.Popen(['iwconfig', interface, 'channel', str(channel)])
            time.sleep(1)


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
            speak('Wi-Fi device found')

    now = datetime.datetime.now()
    print('{} {} {}'.format(now, bssid, strength))


def main():
    args = arg_parser.parse_args()
    config['interface'] = args.interface
    config['timeout'] = args.timeout
    config['threshold'] = args.threshold
    thread = threading.Thread(target=channel_hopper,
                              args=(config['interface'],))
    thread.setDaemon(True)
    thread.start()
    sniff(iface=config['interface'], prn=PacketHandler)

if __name__ == '__main__':
    main()
