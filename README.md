# simpleio
I/O Simplified - network, serial, and beyond!

## `network_transport`

### `TLS`

To set up certificates for TLS (v1.3), follow these steps:

1. Create certificate authority: `openssl req -new -x509 -days 3650 -keyout ca.key -out ca.crt -subj "/C=US/ST=Test/L=Test/O=TestCA/CN=TestRootCA"`.
Enter a passphrase; call it `PEM`. 
2. Create receiver key: `openssl req -new -newkey rsa:4096 -keyout receiver.key -out receiver.csr -nodes -subj "/C=US/ST=Test/L=Test/O=TestServer/CN=localhost"`
3. Create receiver cert: `openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650`. Enter `PEM`
passphrase when prompted.
4. Create sender key: `openssl req -new -newkey rsa:4096 -keyout sender.key -out sender.csr -nodes -subj "/C=US/ST=Test/L=Test/O=TestClient/CN=client"`.
5. Create sender cert: `openssl x509 -req -in sender.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out sender.crt -days 3650`. Enter `PEM`
passphrase when prompted.
6. Check certs are valid:
`openssl verify -CAfile ca.crt receiver.crt`
`openssl verify -CAfile ca.crt sender.crt`
Results should show `OK`.