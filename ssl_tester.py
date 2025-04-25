#!/usr/bin/python

import json
import logging
import requests
import ssl
import socket
import OpenSSL.crypto as crypto
import sys
import time

from ssl_utils import get_config, get_splunk_hec_config, set_logging


def send2Splunk(event: dict, splunk_config: tuple[str, dict], splunk_hec: dict) -> None:
    url = splunk_hec.get("url")
    token = splunk_hec.get("token")

    index = splunk_config[1].get("index", "main")
    source = splunk_config[1].get("source", "ssl_tester")
    sourcetype = splunk_config[1].get("sourcetype", "ssl_tester:json")

    hec_url = f"http://{url}/services/collector/event"
    auth_header = {"Authorization": f"Splunk {token}"}

    payload = {
        "time": int(time.time()),
        "index": index,
        "sourcetype": sourcetype,
        "source": source,
        "host": "ssl_tester",
        "event": event,
    }
    payloadstr = json.dumps(payload)
    try:
        response = requests.post(
            hec_url, headers=auth_header, data=payloadstr, verify=False, timeout=10
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: {e}")
        sys.exit()


def verify_ssl_certificate(hostname: str, port: int, annotation: str) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert(True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

                cert_subject = crypto.X509Name(x509.get_subject()).get_components()
                c_subject = [
                    ({str(k, encoding="utf-8"): str(v, encoding="utf-8")})
                    for k, v in list(cert_subject)
                ]
                cert_issuer = crypto.X509Name(x509.get_issuer()).get_components()
                c_issuer = [
                    ({str(a, encoding="utf-8"): str(b, encoding="utf-8")})
                    for a, b in list(cert_issuer)
                ]

                san = ""
                cert_type = ""
                ext_count = x509.get_extension_count()
                for i in range(0, ext_count):

                    ext = x509.get_extension(i)
                    if "subjectAltName" in str(ext.get_short_name()):
                        san = ext.__str__()
                    if "certificatePolicies" in str(ext.get_short_name()):
                        cert_type = ext.__str__()

                        if "Policy: 2.23.140.1.2.1" in cert_type:
                            cert_type = "DV"
                        elif "Policy: 2.23.140.1.2.2" in cert_type:
                            cert_type = "OV"
                        elif "Policy: 2.23.140.1.1" in cert_type:
                            cert_type = "EV"
                        else:
                            cert_type = cert_type

                public_key = x509.get_pubkey()
                key_type = "RSA" if public_key.type() == crypto.TYPE_RSA else "DSA"
                key_length = public_key.bits()
                data = {
                    "annotation": annotation,
                    "dest_port": port,
                    "dest": hostname,
                    "conn_cipher": ssock.cipher(),
                    "conn_selected_alpn": ssock.selected_alpn_protocol(),
                    "conn_version": ssock.version(),
                    "cert_subject": c_subject,
                    "cert_issuer": c_issuer,
                    "cert_expired": x509.has_expired(),
                    "cert_version": x509.get_version(),
                    "cert_notAfter": time.strftime(
                        "%Y-%m-%d %H:%M:%SZ",
                        time.strptime(
                            str(x509.get_notAfter(), encoding="utf-8"),
                            "%Y%m%d%H%M%SZ",
                        ),
                    ),
                    "cert_notBefore": time.strftime(
                        "%Y-%m-%d %H:%M:%SZ",
                        time.strptime(
                            str(x509.get_notBefore(), encoding="utf-8"), "%Y%m%d%H%M%SZ"
                        ),
                    ),
                    "digest_md5": x509.digest("md5").decode(),
                    "digest_sha1": x509.digest("sha1").decode(),
                    "digest_sha256": x509.digest("sha256").decode(),
                    "cert_algorithm": x509.get_signature_algorithm().decode(),
                    "cert_san": san,
                    "cert_keytype": key_type,
                    "cert_keylength": key_length,
                    "cert_type": cert_type,
                }
                return data
    except socket.timeout:
        data = {"hostname": hostname, "message": "Connection timed out"}
        return data
    except ssl.SSLCertVerificationError as verify_error:
        data = {"hostname": hostname, "message": str(verify_error)}
        return data
    except ssl.SSLError as e:
        data = {"hostname": hostname, "message": str(e)}
        return data
    except Exception as uncaught:
        data = {"hostname": hostname, "message": str(uncaught)}
        return data


if __name__ == "__main__":
    # Load config
    logger, splunk, ssltester = get_config()
    set_logging(logger)

    # Load Splunk HEC parameters
    splunk_hec = get_splunk_hec_config()
    endpoints = ssltester[1]["endpoints"]

    if not endpoints:
        logging.error("No endpoints found in config file")
        sys.exit()

    for entry in endpoints:
        endpoint = entry.get("endpoint")
        port = entry.get("port", 443)
        annotation = entry.get("annotation", "")
        verify_response = verify_ssl_certificate(endpoint, port, annotation)
        send2Splunk(verify_response, splunk, splunk_hec)
