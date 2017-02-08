# coding:utf-8
import argparse
import logging
import subprocess
import threading
import time
from logging.handlers import RotatingFileHandler

import redis

import yaml
import scapy.config
from scapy.layers.dot11 import (
    Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon, sniff)
from wifimonitor.tts import speak
from wifimonitor.mac import get_mac_vendor
from wifimonitor.plugin import PluginManager

logger = logging.getLogger(__name__)
redis_connection = redis.Redis()
config = {}
devices = {}

plugin_manager = PluginManager()

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-c', '--config',
                        help='Configuration file.')
arg_parser.add_argument('-l', '--log-file',
                        help='Log file')
arg_parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output.')


def channel_hopper(iface, channels):
    while 1:
        for channel in channels:
            logger.debug('hopping channel {}'.format(channel))
            subprocess.Popen([
                'iwconfig', iface, 'channel', str(channel)
            ]).wait()
            time.sleep(1)


def handle_expire():
    pubsub = redis_connection.pubsub()
    pubsub.psubscribe('__key*__:expired')
    for msg in pubsub.listen():
        if msg['type'] != 'pmessage':
            continue

        usernames = [
            user['name']
            for user in config['users']
        ] if 'users' in config else []

        key = msg['data'].decode('utf-8')
        logger.info('{} disconnected.'.format(data))

        if key in usernames:
            plugin_manager.user_offline(key)
        else:
            plugin_manager.process_disconnect(key_name=key)


def get_station_mac(pkt):
    ds_field = pkt.getfieldval('FCfield') & 0x03
    if pkt.type == 0:
        if any(pkt.haslayer(layer)
               for layer in (Dot11ProbeResp, Dot11Beacon)):
            redis_connection.sadd('aps', pkt.addr2)
            return
        elif pkt.haslayer(Dot11ProbeReq):
            return

    if ds_field == 0:  # to-DS: 0, from-DS: 0
        src = pkt.addr2
    elif ds_field == 1:  # to-DS: 1, from-DS: 0
        src = pkt.addr2
    elif ds_field == 2:  # to-DS: 0, from-DS: 1
        redis_connection.sadd('aps', pkt.addr2)
        return
    elif ds_field == 3:  # to-DS: 1, from-DS: 1
        return

    if redis_connection.sismember('aps', src):
        return

    if src == '00:00:00:00:00:00':
        return

    return src


def packet_filter(pkt):
    if not pkt.haslayer(Dot11):
        return

    strength = get_signal_strength(pkt)
    mac = get_station_mac(pkt)

    if strength < config['threshold']:
        return

    if mac is None:
        return

    if is_ignored_prefix(mac):
        return

    return True


def packet_handler(pkt):
    strength = get_signal_strength(pkt)
    mac = get_station_mac(pkt)

    if is_new_entry(mac):
        if mac in devices:
            username = devices[mac]['username']
            device_name = devices[mac]['devicename']
            ignored = devices[mac]['ignored']

            plugin_manager.process_connect(
                mac=mac,
                strength=strength,
                username=username,
                device_name=device_name,
                ignored=ignored)
            if not ignored:
                speak('Welcome {}'.format(username))
        else:
            vendor_name = get_mac_vendor(mac)
            plugin_manager.process_connect(
                mac=mac,
                strength=strength,
            )
            speak('Welcome guest')

        logger.info('{} {} "{}"'.format(
            mac, strength, device_name if mac in devices else vendor_name))

    update_mac(mac, strength)
    plugin_manager.process_update(mac=mac, strength=strength)

    logger.debug('{} {}'.format(mac, strength))


def update_mac(mac, strength):
    timestamp = time.time()
    pipeline = redis_connection.pipeline()

    def update(name, strength):
        pipeline.hsetnx(name, 'since', timestamp)
        pipeline.hset(name, 'lastseen', timestamp)
        pipeline.hset(name, 'strength', strength)
        pipeline.expire(name, config['timeout'])

    if mac in devices:
        username = devices[mac]['username']
        device_name = devices[mac]['devicename']
        ignored = devices[mac]['ignored']
        update(device_name, strength)

        if not ignored:
            if not redis_connection.exists(username):
                plugin_manager.user_online(username)
            update(username, strength)

    else:
        update(mac, strength)

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
    if 'ignored_prefixes' not in config:
        return False
    return any(
        mac.startswith(prefix)
        for prefix in config['ignored_prefixes'])


def register_devices(config):
    if 'users' not in config:
        return

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
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    channels = config.get('channels', range(1, 13+1))

    plugin_dir = config.get('plugin_dir', None)
    if plugin_dir:
        plugin_manager.load_plugins(plugin_dir)

    hopper = threading.Thread(target=channel_hopper,
                              args=(config['interface'], channels))
    hopper.setDaemon(True)
    hopper.start()

    expire_handler = threading.Thread(target=handle_expire)
    expire_handler.setDaemon(True)
    expire_handler.start()

    speak('Starting scanner')
    scapy.config.conf.iface = config['interface']
    sniff(iface=config['interface'], prn=packet_handler,
          lfilter=packet_filter, filter='not subtype beacon', store=False)

if __name__ == '__main__':
    main()
