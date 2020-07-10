# ja3s-fingerprinting


<h2>Introduction</h2>
Scripts for JA3 and JA3S fingerprinting

(c) Petr Matousek, 2020
Contact: matousp@fit.vutbr.cz

The scripts were developed under frame of the project Integrated platform for analysis of digital data from security incidents (Tarzan), 2017-2020

A list of scripts:
  - get-ja3s.sh - extracts TLS and DNS data from a PCAP file and creates JA3 and JA3S fingerprints
  - dns2list.pl - parser that reads CSV output of tshark and processes DNS data
  - tlss2list.pl - parser that reads CSV output of tshark, processes TLS handshakes and computes JA3 and JA3S hashes
  - ja3db.pl - script that reads JA3 and JA3S fingerprints and creates JA3 fingerprint database. It also classifies unknown traffic based on the learnt fingerprints
