import argparse
import datetime
import logging
import redis
import yaml

from logging.handlers import RotatingFileHandler

from scapy.fields import EnumField
from scapy.layers.dot11 import Dot11Auth, Dot11ProbeReq, Dot11ProbeResp, sniff

from wifimonitor.tts import speak
from wifimonitor.mac import get_mac_vendor

logger = logging.getLogger(__name__)
redis_connection = redis.Redis()
config = {}
devices = {}

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-c', '--config',
                        help='Configuration file.')
arg_parser.add_argument('-l', '--log-file',
                        help='Log file')


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
    if not any(pkt.haslayer(layer) for layer in (
            Dot11Auth, Dot11ProbeReq, Dot11ProbeResp)):
        return

    mac_address = get_station_bssid(pkt)
    # 0 dB == 255
    strength = ord(pkt.notdecoded[-4])

    if strength < config['threshold']:
        return

    if mac_address in devices and not devices[mac_address]['ignored']:
        username = devices[mac_address]['username']
        vendor_part = mac_address[:8]
        pipeline = redis_connection.pipeline()
        pipeline.incr(username)
        pipeline.expire(username, config['timeout'])
        pipeline.incr(vendor_part)
        pipeline.expire(vendor_part, config['timeout'])
        result = pipeline.execute()
        count = result[0]

        if count == 1:
            device_name = '{}:{}'.format(
                username, devices[mac_address]['name'])
            speak('Welcome {}'.format(username))

            logger.info('{} {} "{}"'.format(
                mac_address, strength, device_name
            ))
    elif mac_address not in devices:
        vendor_part = mac_address[:8]
        pipeline = redis_connection.pipeline()
        pipeline.incr(vendor_part)
        pipeline.expire(vendor_part, config['timeout'])
        result = pipeline.execute()
        count = result[0]

        if count == 1:
            vendor = get_mac_vendor(mac_address)
            speak('Welcome guest')
            logger.info('{} {} "{}"'.format(
                 mac_address, strength, vendor
            ))

    logger.debug('{} {}'.format(mac_address, strength))


def register_devices(config):
    for user in config['users']:
        for mac, device_name in user['devices'].items():
            devices[mac] = {
                'username': user['name'],
                'name': device_name,
                'ignored': False,
            }
        if 'ignored-devices' in user:
            for mac, device_name in user['ignored-devices'].items():
                devices[mac] = {
                    'username': user['name'],
                    'name': device_name,
                    'ignored': True,
                }


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

    register_devices(config)

    if args.log_file:
        handler = RotatingFileHandler(args.log_file)
    else:
        handler = logging.StreamHandler()

    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    speak('Starting scanner')
    sniff(iface=config['interface'], prn=PacketHandler,
          filter='type mgt and '
          '(subtype auth or subtype probe-req or subtype probe-resp)',
          store=False)

if __name__ == '__main__':
    main()
