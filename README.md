# Wireshark dissector for Titanfall and Apex Legends

A Wireshark dissector for Respawn's Source engine's encrypted packet format used in Titanfall and Apex Legends games.

If the protocol isn't automatically detected based on UDP ports, you need to right click the packet and manually change its protocol to `TITANFALLPROTO`.

You need to provide the correct decryption key in protocol settings in order to successfully decrypt a packet (right click packet -> Protocol Preferences -> Titanfall Protocol Decryptor -> Decryption key).

The default decryption key for Titanfall 2 is: `WDNWLmJYQ2ZlM0VoTid3Yg==`

To access the decrypted packet data, click on a packet and expand the following in the lower pane: Titanfall Protocol Decryptor -> Raw decrypted data -> Decrypted data. The lowest pane will now have the data displayed for further examination. The raw decrypted data isn't further processed by this dissector.

Screenshot:
![screenshot](https://user-images.githubusercontent.com/5182588/166333639-010bb529-30f5-4209-937f-a69214ab7bda.png)

## Installation

### Linux

First compile+install luagcrypt (yes, it's that simple):
```
git clone https://github.com/Lekensteyn/luagcrypt.git
cd luagcrypt
sudo luarocks make --lua-version 5.2
cd ..
```

Then:
```
git clone https://github.com/p0358/wireshark_titanfallproto.git
cd wireshark_titanfallproto
mkdir -p ~/.local/lib/wireshark/plugins/
cp {base64,titanfallproto}.lua ~/.local/lib/wireshark/plugins/
```

### Windows

1. Grab DLL for Windows and latest Wireshark from: https://github.com/Lekensteyn/luagcrypt
2. Put it into the plugins dir in Wireshark installation at Program Files
3. Copy the Lua files from this repo into plugins dir in Wireshark dir in %appdata%
4. Hope it works
5. Cry if not
