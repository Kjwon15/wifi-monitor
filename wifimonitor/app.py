import datetime
import redis
import subprocess
import threading
import time

from scapy.fields import EnumField
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.all import sniff

from wifimonitor.tts import speak

redis_connection = redis.Redis()
TIMEOUT = 60 * 5  # 5 minutes

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
        return (1 << field.names.index([value])) & getattr(pkt, field_name) != 0


def get_station_bssid(pkt):
    if pkt.haslayer(Dot11ProbeReq) or hasflag(pkt, 'FCfield', 'to-DS'):
        return pkt.addr2
    else:
        return pkt.addr1

def PacketHandler(pkt):
    bssid = get_station_bssid(pkt)
    # Broadcast and multicast
    if bssid == 'ff:ff:ff:ff:ff:ff' or \
       bssid.startswith('01:00:5e'):
        return
    # 0 dB == 256
    strength = ord(pkt.notdecoded[-4])
    if strength >= 200:
        pipeline = redis_connection.pipeline()
        pipeline.incr(bssid)
        pipeline.expire(bssid, TIMEOUT)
        result = pipeline.execute()
        count = result[0]
        if count == 5 and strength >= 200:
            speak('Wi-Fi device found')

    now = datetime.datetime.now()
    print('{} {} {}'.format(now, bssid, strength))


def main():
    interface = 'wlan1'
    thread = threading.Thread(target=channel_hopper, args=(interface,))
    thread.setDaemon(True)
    thread.start()
    sniff(iface=interface, prn=PacketHandler)

if __name__ == '__main__':
    main()
