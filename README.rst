Wi-Fi monitor
=============

Detect intruders or say hello to you using Wi-Fi monitor mode.


Install
-------

Wi-Fi monitor requies **mpg321**, **redis** to speak google TTS.
Enable [Redis expired key subscribe](https://redis.io/topics/notifications) to log expired devices.

.. code-block:: console

   $ sudo apt-get install mpg321 redis-server
   $ redis-cli config set notify-keyspace-events KEA


