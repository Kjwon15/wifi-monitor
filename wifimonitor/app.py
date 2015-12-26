import argparse
import datetime
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


def channel_hopper(iface, channels):
    while 1:
        for channel in channels:
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

    mac = get_station_bssid(pkt)
    if mac is None:
        return

    if is_ignored_prefix(mac):
        return

    strength = get_signal_strength(pkt)

    if strength < config['threshold']:
        return

    if is_new_entry(mac):
        if mac in devices:
            username = devices[mac]['username']
            device_name = devices[mac]['devicename']
            ignored = devices[mac]['ignored']
            if not ignored:
                speak('Welcome {}'.format(username))
        else:
            vendor_name = get_mac_vendor(mac)
            speak('Welcome guest')

        logger.info('{} {} "{}"'.format(
            mac, strength, device_name if mac in devices else vendor_name))

    update_mac(mac)

    logger.debug('{} {}'.format(mac, strength))


def update_mac(mac):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pipeline = redis_connection.pipeline()
    if mac in devices:
        username = devices[mac]['username']
        device_name = devices[mac]['devicename']
        ignored = devices[mac]['ignored']
        pipeline.setnx(device_name, timestamp)
        pipeline.expire(device_name, config['timeout'])

        if not ignored:
            pipeline.setnx(username, timestamp)
            pipeline.expire(username, config['timeout'])

    else:
        pipeline.setnx(mac, timestamp)
        pipeline.expire(mac, config['timeout'])

    pipeline.execute()


def get_signal_strength(pkt):
    # 0 dB == 255
    strength = ord(pkt.notdecoded[-4])
    return strength


def is_new_entry(mac):
    if is_ignored_prefix(mac):
        return False

    if mac in devices:
        ignored = devices[mac]['ignored']
        username = devices[mac]['username']
        device_name = devices[mac]['devicename']
        key_name = username if not ignored else device_name
    else:
        key_name = mac

    return not redis_connection.exists(key_name)


def is_ignored_prefix(mac):
    return any(
        mac.startswith(prefix)
        for prefix in config['ignored_prefixes'].keys())


def register_devices(config):
    for user in config['users']:
        if 'devices' in user:
            for mac, device_name in user['devices'].items():
                devices[mac] = {
                    'username': user['name'],
                    'devicename': '{}:{}'.format(user['name'], device_name),
                    'ignored': False,
                }
        if 'ignored-devices' in user:
            for mac, device_name in user['ignored-devices'].items():
                devices[mac] = {
                    'username': user['name'],
                    'devicename': '{}:{}'.format(user['name'], device_name),
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
                              args=(config['interface'], config['channels']))
    hopper.setDaemon(True)
    hopper.start()

    speak('Starting scanner')
    sniff(iface=config['interface'], prn=packet_handler,
          store=False)

if __name__ == '__main__':
    main()
