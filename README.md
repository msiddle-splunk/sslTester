# sslTester

A simple script for monitoring certificate expiry and other data points.

The script will create a socket to each host defined in config.yaml, read the certificate information returned, and close the connection.

## Configuration

The script requires two configurations:

-   Environment Variables set

    -   HEC_ENDPOINT
    -   HEC_TOKEN

-   config.yaml
    -   Logging path
        -   default path is /tmp/sslTester\_{date}.log
        -   If no config.yaml is found, an error will be logged to /tmp/sslTester\_{date}.log
    -   Splunk metadata (index, source, sourcetype)
    -   Endpoints to test (endpoint, port, annotation)

Note - annotation can be used to add context for the endpoint queried i.e. front end, api

## Use Cases

-   Answer questions such as:
    -   When do the certificates on my hosts/services expire?
    -   Which issuers do we get certificates from?
    -   Which SANs are set for a certificate?
    -   Are services/hosts being provisioned using organisation-defined best practices such as TLS versions, Issuer information, certificate type (DV, OV)?

## Example Search for Expiry Date

```
index=main sourcetype=ssl_tester:json source=ssl_tester
| eval days_left = floor((strptime(cert_notAfter, "%Y-%m-%d %H:%M:%SZ")-now())/86400)
| stats latest(days_left) AS "Days until Expiration" latest(cert_notAfter) AS "Expiry Date" by dest
| where 'Days until Expiration' < 30
```
