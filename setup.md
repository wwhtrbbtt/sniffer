# Setup sniffer on MacOS

## Airport CLI tool

**Symlink airport**

```
$ sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport
```

This makes the `airport` command available to you.

**Get available networks**

```
$ sudo airport en1 -s
```

## Monitor mode

**Open wireless diagnostics**

```
$ open /System/Library/CoreServices/Applications/Wireless\ Diagnostics.app/Contents/MacOS/Wireless\ Diagnostics
```

**Window -> sniffer -> start**

## Start CLI sniffer

```
$ sudo python3 sniff.py
```
