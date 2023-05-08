# Wireshark dissector for Titanfall and Apex Legends

A Wireshark dissector for Respawn's Source engine's encrypted packet format used in Titanfall and Apex Legends games.

If the protocol isn't automatically detected based on UDP ports, you need to right click the packet and manually change its protocol to `TITANFALLPROTO` (click Decode As, adjust the port and select the protocol under Current field).

You need to provide the correct decryption key in protocol settings in order to successfully decrypt a packet (right click packet -> Protocol Preferences -> Titanfall Protocol Decryptor -> Decryption key).

The default decryption key for Titanfall 2 is: `WDNWLmJYQ2ZlM0VoTid3Yg==`

To access the decrypted packet data, click on a packet and expand the following in the lower pane: Titanfall Protocol Decryptor -> Raw decrypted data -> Decrypted data. The lowest pane will now have the data displayed for further examination. The raw decrypted data isn't further processed by this dissector.

Screenshot:
![screenshot](https://user-images.githubusercontent.com/5182588/166333639-010bb529-30f5-4209-937f-a69214ab7bda.png)

## Installation

### Linux

First compile+install luagcrypt (yes, it's that simple, it shall automatically get installed into `/usr/local/lib/lua/5.2/`):
```
git clone https://github.com/Lekensteyn/luagcrypt.git
cd luagcrypt
sudo luarocks make --lua-version 5.2
cd ..
```
Note for Ubuntu users: have you might need to install `lua5.2` and `liblua5.2-dev` and uninstall `lua5.1` and `liblua5.1-dev`, because otherwise luarocks will ignore your will to use 5.2, and also rename `/usr/local/lib/lua/5.2/luagcrypt_scm_0-luagcrypt.so` to `/usr/local/lib/lua/5.2/luagcrypt.so`. It just works on Arch on the other hand.

Then:
```
git clone https://github.com/p0358/wireshark_titanfallproto.git
cd wireshark_titanfallproto
mkdir -p ~/.local/lib/wireshark/plugins/
cp {base64,titanfallproto}.lua ~/.local/lib/wireshark/plugins/
```

### Windows (lazy)

1. Grab conveniently compiled `luagcrypt.dll` from this repo (compatible with libgcrypt-20.dll v1.10.1.0 that's already bundled with latest Wireshark)
2. Put it into the main dir of Wireshark installation at Program Files
3. Copy the `.lua` files from this repo into `%appdata%\Wireshark\plugins`

### Windows (compile manually)

1. Clone this repo to compile luagcrypt manually: https://github.com/Lekensteyn/luagcrypt
2. Put luarocks.exe inside of the dir, extracted from latest zip here: http://luarocks.github.io/luarocks/releases/ (`luarocks-*-windows-64.zip (luarocks.exe stand-alone Windows 64-bit binary)`)
3. Download latest libgcrypt headers etc from: https://dev-libs.wireshark.org/windows/packages/libgcrypt/ and unpack the folders `bin`, `include`, `lib` from `installed/x64-windows` into the dir
4. Run `./luarocks make --lua-version 5.2 LIBGCRYPT_DIR=.`
5. Copy the compiled `luagcrypt.dll` into the main dir of Wireshark installation at Program Files
6. Copy the `.lua` files from this repo into `%appdata%\Wireshark\plugins`
