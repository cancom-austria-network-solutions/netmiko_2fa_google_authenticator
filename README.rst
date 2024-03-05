Introduction
==================


netmiko_2fa_google_authenticator is an out of tree netmiko driver for 2FA with google-authenticator.


Installation
------------

Install the netmiko google-authenticator driver by running:

    pip3 install netmiko_2fa_google_authenticator

Usage
-----

.. code-block:: python

    from netmiko import ConnectHandler
    import  netmiko_2fa_google_authenticator

    target = {
        'device_type': '2fa_google_authenticator',
        'target_device_type': 'linux',
        'ip': ssh_host, # ip of host
        'username': ssh_username, # username
        'password': [ssh_password,authenticator_otp], # password list [<server_password>,<google otp>]
        'port': 22,
    }

    target2 = {
        'device_type': '2fa_google_authenticator',
        'target_device_type': 'linux',
        'ip': ssh_host, # ip of host
        'username': ssh_username, # username
        'password': ssh_password, # password <server_password>
        'port': 22,
        'otp_secret': authenticator_secret # secret shown by google-authenticator at setup
        
    }

    ssh = ConnectHandler(**target)
    print(ssh.send_command("ls /"))
    ssh = ConnectHandler(**target2) 
    print(ssh.send_command("ls /"))

Contribute
----------

- Issue Tracker: https://github.com/jinjamator/netmiko_2fa_google_authenticator/issues
- Source Code: https://github.com/jinjamator/netmiko_2fa_google_authenticator

License
-----------------

This project is licensed under the Apache License Version 2.0