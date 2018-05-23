# s96util

This utility takes care of the following functions:

- Display device info
- Dump device configuration
- Personalize the device

## Sample output
```
bash$ s96util -h
Usage: /tmp/secure96 <option>
Available options:
 -i, --info            Display device info
 -d, --dump-config      Dump config zone
 -p, --personalize     Write config and data
 -h, --help            Display this message
 -v, --version         Display version
```

Device info:
```
bash$ s96util -i
Device Revision:    00020009
Serial Number:      0123a225a571d327ee
Config Zone locked:  Yes
Data Zone locked:   Yes
OTP mode:           Consumption
```

Device config:
```
bash$ s96util -c | xxd
0000000: 0123 a225 0009 0400 a571 d327 ee0e 0100  .#.%.....q.'....
0000010: c800 5500 8080 8020 8080 8030 8080 80a0  ..U.... ...0....
0000020: 8080 80b0 8048 c049 8080 8080 0000 0000  .....H.I........
0000030: 0080 0080 ff00 ff00 ff00 ff03 ff00 ff00  ................
0000040: ff00 ff00 ffff ffff ffff ffff ffff ffff  ................
0000050: ffff ffff 0000 0000                      ........
```

Personalization:
```
bash$ s96util -p
WARNING: Personalizing the device is an one-time operation! Continue? [yN] y
Done
```

