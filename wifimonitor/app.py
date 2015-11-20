import argparse
import logging
import subprocess
import threading
import time
from logging.handlers import RotatingFileHandler

import redis

import yaml
from scapy.layers.dot11 import Dot11, sniff
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


def channel_hopper(iface):
    rng = range(1, 13 + 1)
    while 1:
        for channel in rng:
            logger.debug('hopping channel {}'.format(channel))
            subprocess.Popen([
                'iwconfig', iface, 'channel', str(channel)
            ]).wait()
            time.sleep(1)


def get_station_bssid(pkt):
    ds_field = pkt.getfieldval('FCfield') & 0x03
    if pkt.type == 0 and pkt.subtype == 8:
        return

    if ds_field == 0:  # to-DS: 0, from-DS: 0
        src = pkt.addr2
    elif ds_field == 1:  # to-DS: 1, from-DS: 0
        src = pkt.addr2
    elif ds_field == 2:  # to-DS: 0, from-DS: 1
        return
    elif ds_field == 3:  # to-DS: 1, from-DS: 1
        return

    return src


def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return

    mac_address = get_station_bssid(pkt)
    if mac_address is None:
        return

    # 0 dB == 255
    strength = ord(pkt.notdecoded[-4])

    if strength < config['threshold']:
        return

    if mac_address in devices:
        ignored = devices[mac_address]['ignored']
        username = devices[mac_address]['username']
        vendor_part = mac_address[:8]

        pipeline = redis_connection.pipeline()
        pipeline.incr(
            username if not ignored else mac_address)
        pipeline.expire(username, config['timeout'])
        pipeline.incr(vendor_part)
        pipeline.expire(vendor_part, config['timeout'])
        result = pipeline.execute()
        count = result[0]

        if count == 1:
            device_name = '{}:{}'.format(
                username, devices[mac_address]['name'])
            if not ignored:
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

    hopper = threading.Thread(target=channel_hopper,
                              args=(config['interface'],))
    hopper.setDaemon(True)
    hopper.start()

    speak('Starting scanner')
    sniff(iface=config['interface'], prn=packet_handler,
          store=False)

if __name__ == '__main__':
    main()
