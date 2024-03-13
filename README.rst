Introduction
==================

netmiko_2fa_google_authenticator is an out of tree netmiko driver for 2 factor authentication based on TOTP (timed one time passwords) as the google-authenticator app generates them.
As security demands increase, many internet facing linux machines are secured by 2fa. As some of our customers provide linux machines as ssh jumphosts for automation, we built this plugin.
It is compatible and extensively tested with `netmiko_multihop <https://github.com/cancom-austria-network-solutions/netmiko_multihop>`_.


Installation
------------

Install the netmiko google-authenticator driver by running:

    pip3 install netmiko_2fa_google_authenticator

Usage
-----

The usage is pretty straightforward, just import the module after importing netmiko. This will register a new platform in netmiko, which is capable to do TOPT 2FA (MFA)
As target_device_type currently only linux is supported, but other platforms can be supported easily. 

There are 2 modes of operation. Either provide password as list of machine password and TOTP or provide the shared secret. If you provide the shared secret, the driver will generate TOTPs at it's own, this means that you perhaps breaking your company's security requirements, so be careful.


.. code-block:: python

    from netmiko import ConnectHandler
    import  netmiko_2fa_google_authenticator

    target = {
        'device_type': '2fa_google_authenticator',
        'target_device_type': 'linux',
        'ip': ssh_host, # ip of host
        'username': ssh_username, # username
        'password': [ssh_password,authenticator_otp], # password list [<server_password>,<google TOTP>]
        'port': 22,
    }

    target2 = {
        'device_type': '2fa_google_authenticator',
        'target_device_type': 'linux',
        'ip': ssh_host, # ip of host
        'username': ssh_username, # username
        'password': ssh_password, # password <server_password>
        'port': 22,
        'otp_secret': authenticator_secret # secret shown by google-authenticator at setup, warning this means, netmiko_2fa_google_authenticator generates TOTPs autonomous.
        
    }

    ssh = ConnectHandler(**target)
    print(ssh.send_command("ls /"))
    ssh = ConnectHandler(**target2) 
    print(ssh.send_command("ls /"))

Contribute
----------

- Issue Tracker: https://github.com/cancom-austria-network-solutions/netmiko_2fa_google_authenticator/issues
- Source Code: https://github.com/cancom-austria-network-solutions/netmiko_2fa_google_authenticator

License
-----------------

This project is licensed under the Apache License Version 2.0