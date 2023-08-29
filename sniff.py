import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import hashlib

load_layer("tls")

conf.use_pcap = True



def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def calculate_ja3(tls) -> str:
    # TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvesPointFormats

    grease = [
        "0X0A0A",
        "0X0A0A",
        "0X1A1A",
        "0X2A2A",
        "0X3A3A",
        "0X4A4A",
        "0X5A5A",
        "0X6A6A",
        "0X7A7A",
        "0X8A8A",
        "0X9A9A",
        "0XAAAA",
        "0XBABA",
        "0XCACA",
        "0XDADA",
        "0XEAEA",
        "0XFAFA",
        "0XA0A",
    ]

    # Get Version
    version = tls.msg[0].version

    # Get Ciphers
    ciphers = "-".join(
        [str(s) for s in tls.msg[0].ciphers if hex(s).upper() not in grease])

    # Get Extensions
    tmp = []
    for e in tls.msg[0].ext:
        # We dont want grease or padding
        if hex(e.type).upper() not in grease and e.type != 21:
            tmp.append(str(e.type))
    extensions = "-".join(tmp)

    # Elliptic Curves
    tmp = []
    for e in tls.msg[0].ext:
        if e.type == 10:
            for c in e.groups:
                if hex(c).upper() not in grease:
                    tmp.append(str(c))
    curves = "-".join(tmp)

    # Points
    points = ""
    for e in tls.msg[0].ext:
        if e.type == 11:
            points = "-".join([str(p) for p in e.ecpl])

    return f"{version},{ciphers},{extensions},{curves},{points}"


def handle_pkg(pkg) -> None:
    # print(pkg)
    # Check if TLS package
    if TLS in pkg:
        tls = pkg["TLS"]
        if "Client Hello" in str(pkg.summary()):
            if not hasattr(tls, "msg"):
                # print("No msg in tls")
                return
            if len(tls.msg) == 0:
                # print("extension len = 0")
                return
            if not hasattr(tls.msg[0], "ext"):
                # print("No extensions")
                return
            sn = ""
            for i in tls.msg[0].ext:
                if i.type == 0:
                    sn = i.servernames[0].servername.decode()

            print(f"[+] {md5(calculate_ja3(tls))} -> {sn}")


sniff(prn=handle_pkg, monitor=True, iface="en0")
