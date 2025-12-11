# wireshark-ptp
Simple plugin for wireshark to parse Hardware TImestamped PTP packets

Without this plugin, Wireshark does not understand Hardware timestamped PTP Packets.

The Ethernet frames are hardware timestamped with the current wall clock time in a 2 x 32 bit format, representing nanoseconds since 1970-01-01 (UNIX epoch)

Example Frame:

```
0000   01 00 5e 00 01 81 ec 46 70 0a c2 e3 00 2f 18 7f   ..^....Fp..../..
0010   de 2c 82 f4 08 37 08 00 45 00 00 48 19 0b 00 00   .,...7..E..H....
0020   05 11 b0 dd 0a 4a ff f1 e0 00 01 81 01 3f 01 3f   .....J.......?.?
0030   00 34 4b 13 00 02 00 2c 7f 00 00 00 00 00 00 00   .4K....,........
0040   00 00 00 00 00 00 00 00 ec 46 70 ff fe 0a c2 e3   .........Fp.....
0050   00 01 8e 04 00 fd 00 00 69 39 77 cb 01 a3 b7 29   ........i9w....)
```

The first bytes in the Frame can be broken down to:

* `01 00 5e 00 01 81` destination mac address (PTP multicast mac address)
* `ec 46 70 0a c2 e3` source mac address
* `00 2f`: length
* `18 7f de 2c`: HW Timestamp high bits
* `82 f4 08 37`: HW Timestamp low bits
* `08 00` Type (IP)

Then follows a standard IP-header and packet.

Without this plugin, Wireshark does not understand this format, and decodes the Frame as `LLC`:

<img width="949" height="294" alt="image" src="https://github.com/user-attachments/assets/00effc29-3010-4cf4-9d0a-f199f5186080" />

With this plugin, the packet format is recognized and the Hardware Timestamp is decoded and the rest of the IP-packet is parsed correctly.

<img width="949" height="294" alt="image" src="https://github.com/user-attachments/assets/e06a7a74-5f5c-4c93-8cfb-dd8c50ddafea" />

The `Logical-Link Control` and `Data` sections are still present in the output, but they can be ignored. Removing them from the output requires a PR to wireshark, and currently this plugin is good enough for my use.


## Installation
Download the file `ptp-hw-timestamp.lua` and put it in your plugins folder - usually something like `$HOME/.config/wireshark/plugins/` and restart wireshark.

Create the folder if it does not exist, and it should be picked up by Wireshark after restart.


