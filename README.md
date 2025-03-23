# `simpleio`
I/O Simplified - network, serial, and beyond!

## Why `simpleio`?

Moving structured data between devices/processes follows the standard pattern of
1. Create a data structure (_define_).
2. Convert the data structure to a byte array (_serialize_).
3. Send the byte array to a receiving process over a system interface (_transport_).
4. Retrieve original data structure in the receiving process (_deserialize_).

Whether the data structure is XML, JSON, or a custom data class, the pattern doesn't
change...

Whether the system interface is shared memory, a serial port, or a network socket, the
pattern doesn't change...

I created `simpleio` because I found myself repeatedly rewriting the same patterns sharing
data between processes and I wanted something simple and generic that I could tweak to
specific needs.

## What is `simpleio`?

Base classes are provided for your convenience; start from [`Message`](./include/simpleio/message.hpp)
to represent your data structure and its serialized representation, and
[`Sender` / `Receiver`](./include/simpleio/transport.hpp) for transporting your
serialized data. Extend `simpleio` to your specific needs; share your work with a PR!

An example XML `Message` is implemented [here](./include/simpleio/xml_message/xml_message.hpp).

Asynchronous `Sender` / `Receiver` examples for common network protocols (UDP, TCP, and TLS) are
[here](./include/simpleio/network_transport).

## Contributing to `simpleio`

_WIP_

There's a VS Code [devcontainer](.devcontainer) provided to ease setup of the developer environment.
Familiarize yourself with the dependencies by looking at the [Dockerfile](.devcontainer/Dockerfile).

## Using `simpleio` in your project

_WIP_

## Miscellanea

### Preparing apps for TLS (Transport Layer Security)

To set up certificates for TLS (v1.3), run the following commands with the `openssl` CLI app (for Linux/OS X):

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
