#StreamSecureChat
StreamSecureChat is a peer-to-peer encrypted chat application that uses a custom stream cipher for secure communication. It encrypts messages using a password-derived keystream and XOR operations, ensuring that all data transmitted between peers remains confidential.

The project demonstrates how to build a simple, lightweight encryption engine and integrate it into a real-time messaging system over TCP sockets.

Features
Password-based keystream generation using a linear congruential generator (LCG)

Symmetric encryption and decryption via XOR cipher

Real-time encrypted chat between two peers (server and client roles)

Threaded receiving and decrypting of messages

Simple command-line interface
