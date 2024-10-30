![btt purple](https://github.com/user-attachments/assets/c1ba727b-9d86-4fbc-be66-acedf0ea91cf)

## Python BitTorrent Client

This repository contains a simple, educational BitTorrent client built in Python. The purpose of this project is to illustrate the inner workings of the BitTorrent protocol, providing insights into how peer-to-peer file-sharing systems function at a fundamental level.

## Features

* Torrent File Parsing: Reads and interprets .torrent files to gather information about the file(s) being shared and the list of tracker URLs.
* Peer Communication: Connects with peers and manages the exchange of "pieces" (blocks of data) using the BitTorrent protocol.
* Download Management: Ensures integrity and completion of the downloaded files by verifying hashes and assembling pieces.
* Tracker Communication: Interacts with trackers to get lists of available peers, keeping the client informed about the network state.


