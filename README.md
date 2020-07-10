# ja3s-fingerprinting
This folder contains scripts for fingerprinting mobile apps using JA3 and JA3S hashes. Originally, the method was developped by John Althouse and others, see https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967. Here, we apply this method on mobile apps and observe reliability and stability of JA3 and JA3S fingerprints. Details about the methods are described in the technical report, see References below. 

The scripts creates JA3+JA3S fingerprint databased based on the given dataset with typical mobile app communication. For selection of fingerprints diractly related to the app we use Server Name Indication (SNI) string obtained from TLS handshake. Depending on the app, the mobile app fingerprint is composed either by JA3+JA3S hashes only, or as combination of JA3+SNI or JA3+JA3S+SNI. 

<h2>Introduction</h2>
The scripts creates JA3 and JA3S fingerprints of mobile apps extracted from TLS and DNS communication of the app in PCAP format in CSV form. The result can be inserted into SQLite DB and later used for comparison with fingerprints of unknown traffic. 

(c) Petr Matousek, 2020 <br>
Contact: matousp@fit.vutbr.cz

The scripts were developed under frame of the project Integrated platform for analysis of digital data from security incidents (Tarzan), 2017-2020

A list of scripts:
  - get-ja3s.sh - extracts TLS and DNS data from a PCAP file and creates JA3 and JA3S fingerprints
  - dns2list.pl - parser that reads CSV output of tshark and processes DNS data
  - tlss2list.pl - parser that reads CSV output of tshark, processes TLS handshakes and computes JA3 and JA3S hashes
  - ja3db.pl - script that reads JA3 and JA3S fingerprints and creates JA3 fingerprint database. It also classifies unknown traffic based on the learnt fingerprints

<h2>Installation</h2>
All scripts were developed and used under FreeBSD system. They can also run under any Linux or MS Windows with the required software. For running scripts, the following software is required:
<ul>
  <li> tshark, version 3.2
  <li> perl, version 5
  <li> required perl modules: Digest::MD5, Getopt::Long, Net::Whois::IP, DBI
</ul>

<h2>User and Programming Guide</h2>
<h3>1. Extracting JA3 and JA3S hashes from a PCAP file</h3>

<tt>Format: get-ja3s.sh \<PCAP\> [\<output DIR\>]</tt>
 
<tt>Example: get-ja3s.sh ../example/viber.pcapng ../example/output</tt>
  
 - The script reads a PCAP file with mobile app communication, extracts selected fields from DNS and TLS packets, and creates JA3 and JA3S hashes. 
 - DNS processing is used for resolution of IP address in TLS handshakes. If DNS data are missing, no resolution is provided. 
 - For DNS resolution,  DNS responses with A and AAAA requests and responses over IPv4 and IPv6 are extracted
 - Extracted domain names are labeled with AD flag if a domain name is part of advertisements or tracking servers. A list of these servers is locally stored in <tt>ad-list.txt</tt> file. Such databases is obtained from the following sources:
   <ul>
     <li> https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext&_=3
     <li> https://hosts-file.net/ad_servers.txt
     <li> https://gitlab.com/ookangzheng/dbl-oisd-nl/raw/master/dbl.txt
     <li> https://github.com/lightswitch05/hosts/blob/master/ads-and-tracking-extended.txt
     <li> https://easylist.to/easylist/easyprivacy.txt
   </ul>
 - DNS domains and TLS entries with AD flag are omitted from fingerprinting because these entries are part of a "noise" created by ad and tracking modules, see the Technical Report in References for explanation. 
 
 The following data are extracted from the PCAP file:
  * From DNS responses: srcIP, dstIP, Query type, Query Name, Number of Answer entries, Number of Authority entries, Type of the response and Response name
  * From TLS handshakes: src IP, dst IP, src port, dst port, TLS handshake type, TLS handshake version, TLS ciphersuite, TLS extension, TLS handshake SNI, TLS supported groups, TLS EC point format, frame time
  
The following output files are created for each input file if they do not exist:
  * <tt>\<filename\>-dns.csv</tt> - sorted DNS fields in CSV format extracted from DNS responses 
  * <tt>\<filename\>-tlss.csv</tt> - TLS fields in CSV format extracted from TLS handshakes (client hello and server hello packets).
  
Further, the <tt>get-ja3s.sh</tt> script calls perl scripts for analyzing CSV files. The following scripts are called:
  * dns2list.pl - processes DNS data in CSV format and creates a full list of resolved entries with AD flag (<tt>\<filename\>-dns-full.csv</tt>) and a short list of resolved entries with IP address, hostname and AD flag only (file <tt>\<filename\>-dns-list.csv</tt>). 
  * tlss2list.pl - processes TLS data in CSV format, computes JA3 and JA3S hashes with excluded GREASE and renegotion values.  The output is a CSV file with JA3 and JA3S fingerprints with added DNS resolution (file <tt>\<filename\>-tls-fullgs.csv</tt>), a short list with SNI, JA3 and JA3s hashes and AD flags (file <tt>\<filename\>-tls-listgs.csv</tt>), a short list without AD entries (file <tt>\<filename\>-tls-noadgs.csv</tt>) and the final CSV file with sorted unique fingerprints without details (file <tt>\<filename\>-tls-ja3gss.csv</tt>). 
  
<h3>2. Processing DNS data</h3>

DNS data in CSV format extracted directly from PCAP file with mobile app communication is processed by the <tt>dns2list.pl</tt> parser that reads CSV raw data, process them and extract interesting values.

<tt>Format: dns2list.pl -f \<CSV_file\> [-short] [-ad] [-whois]</tt>
 
Parameters:
* <tt>-short</tt> prints only IPv4/6 + domains on the output
* <tt>-ad</tt> prints AD flag if a domain name is found in the list of advertisement servers
* <tt>-whois</tt> requests whois resolution of IP addresses; using whois significantly slows down data processing (!). If omitted, output data contains value <tt>not resolved</tt> in OrgName.
 
Examples: 
  * <tt>dns2list.pl -f viber-dns.csv -ad > viber-dns-full.csv</tt>
  * <tt>dns2list.pl -f viber-dns.csv -short -ad > viber-dns-list.csv</tt>
  * <tt>dns2list.pl -f viber-dns.csv -short -ad -whois > viber-dns-list.csv</tt>
    
Output example:
* Full list:
<pre>
10.0.2.3;10.0.2.15;1;aax-eu.amazon-adsystem.com;aax-eu.amazon-adsystem.com;52.94.216.48;AD
10.0.2.3;10.0.2.15;1;aax-eu.amazon-adsystem.com;aax-eu.amazon-adsystem.com;52.94.216.48;AD
10.0.2.3;10.0.2.15;1;aax-eu.amazon-adsystem.com;aax-eu.amazon-adsystem.com;52.94.216.48;AD
</pre>
* Short list:
<pre>
104.127.61.74;not resolved;sb.scorecardresearch.com;AD
104.127.61.90;not resolved;sb.voicefive.com;AD
151.101.114.133;not resolved;identity.mparticle.com;AD
151.101.130.110;not resolved;mobile-collector.newrelic.com;AD
151.101.130.133;not resolved;config2.mparticle.com;AD
</pre>

<h3>3. Processing TLS data</h3>

TLS data in CSV format extracted directly from PCAP file with mobile app communication is processed by the <tt>tlss2list.pl</tt> parser that reads csv output of the tshark, processes TLS handshakes and computes JA3 and JA3S hashes. It also excludes GREASE values from fingerprinting, see RFC 8701, and renegotiation, see RFC 5746.

<tt>Format: tlss2list.pl -f \<CSV_file\> [-dns dns_file] [-list] [-noad]</tt>
 
Parameters:
* <tt>-dns</tt>: includes dns file with resolved IP addresses and AD flags in the following CSV format: IPv4/IPv6 address;whois orgname; domain name;AD flag. 
* <tt>-list</tt> prints a simple ouput: IP address + fingerprint + AD flag, only unique entries
* <tt>-noad</tt> a sorted output without entries with AD flag.
 
Examples: 
  * <tt>tlss2list.pl -f viber-tlss.csv -dns viber-dns.csv > viber-tls-fullgs.csv</tt>
  * <tt>tlss2list.pl -f viber-tlss.csv -dns viber-dns.csv -list > viber-tls-listgs.csv</tt>
  * <tt>tlss2list.pl -f viber-tlss.csv -dns viber-dns.csv -list -noad > viber-tls-noadgs.csv</tt>
    
Output example:
* Full list:
<pre>
SrcIP;DstIP;SrcPort;DstPort;OrgName;SNI;Hostname;AD flag;Version;Client CipherSuite;Client Extensions;Client SG;CEC_fmt;JA3hash;Server CipherSuite;Server Extensions;Server SG;SEC_fmt;JA3S hash
10.0.2.15;104.127.61.74;40474;443;not resolved;sb.scorecardresearch.com;sb.scorecardresearch.com;AD;771;49195-49196-52393-49199-49200-52392-49161-49162-49171-49172-156-157-47-53;0-23-10-11-35-16-5-13;0x0000001d,0x00000017,0x00000018;0;193c522402283ed9e84b8bb38137829f;49200;0-11-35-5-16;;0,1,2;4e3362a4d6bdc0739bcf48fe32243a69
10.0.2.15;104.127.61.74;40498;443;not resolved;sb.scorecardresearch.com;sb.scorecardresearch.com;AD;771;49195-49196-52393-49199-49200-52392-49161-49162-49171-49172-156-157-47-53;0-23-10-11-35-16-5-13;0x0000001d,0x00000017,0x00000018;0;193c522402283ed9e84b8bb38137829f;49200;16;;;0bcfa5ab48fd49e9b452fbea51bf9ff7
</pre>
* Short list:
<pre>
SrcIP;DstIP;OrgName;SNI;AD flag;JA3 hash;JA3S hash
10.0.2.15;104.127.61.74;not resolved;sb.scorecardresearch.com;AD;193c522402283ed9e84b8bb38137829f;4e3362a4d6bdc0739bcf48fe32243a69
10.0.2.15;104.127.61.74;not resolved;sb.scorecardresearch.com;AD;193c522402283ed9e84b8bb38137829f;0bcfa5ab48fd49e9b452fbea51bf9ff7
10.0.2.15;104.127.61.74;not resolved;sb.scorecardresearch.com;AD;193c522402283ed9e84b8bb38137829f;4e3362a4d6bdc0739bcf48fe32243a69
</pre>
* Short list without AD:
<pre>
JA3 hash;SrcIP;DstIP;OrgName;SNI;JA3S hash;Filename
1bff249589c418e6881e847dda91068a;10.0.2.15;151.101.66.202;not resolved;sdk.foursquare.com;f30c69a500705210e6c547d244ffe506;../example/output//accuweather-tlss.csv
1bff249589c418e6881e847dda91068a;10.0.2.15;151.101.66.202;not resolved;sdk.foursquare.com;f30c69a500705210e6c547d244ffe506;../example/output//accuweather-tlss.csv
d5dcde95b8fa38b5062a128f7eff0737;10.0.2.15;172.217.23.202;not resolved;fonts.googleapis.com;3589acf0c85c607d87bcab1a7e1c7ca3;../example/output//accuweather-tlss.csv
</pre>
<h3>4. Building the fingerprint database for mobile apps</h3>
The final list of JA3 and JA3S hashes with SNI related to the mobile app communication created by selection of relevant fields from the TLS short list without AD. The output format is as follows:
<pre>
JA3 hash;SNI;JA3S hash;filename
0529055d554c9da011b745452211c296;api.accuweather.com;4e3362a4d6bdc0739bcf48fe32243a69;../example/output//accuweather-tlss.csv
0529055d554c9da011b745452211c296;api.mapbox.com;0dd6cbec8e8bbaa06efa39ff853972dd;../example/output//accuweather-tlss.csv
193c522402283ed9e84b8bb38137829f;accuweather.brightspotcdn.com;b63e0ce737c366a59bca6a201d4851ef;../example/output//accuweather-tlss.csv
193c522402283ed9e84b8bb38137829f;api.accuweather.com;0bcfa5ab48fd49e9b452fbea51bf9ff7;../example/output//accuweather-tlss.csv
</pre>
However, even this list can contains entries that are caused by the "noise", i.e., traffic that is not unique to the mobile app. What we need is to filter the list so that only genuine entries related to the mobile app will become a part of the fingerprint. For this final selection we use SNI filtering based on keywords related to the app. 

Here is an example of keywords for applications that we observed:
<pre>
App Name;keyword
Boommplay Music;boomplaymusic
Mobilni Banka;mojebanka.cz
Mobilni Banka;mobilnibanka.cz
KB klic;kb.cz
Nextbike;nextbike.net
EquaBank CZ;equa.cz
EquaBank CZ:equamobile.cz
TitTok;tiktok
Duolingo;duolingo
Youtube;youtube
Google Calendar;calendarsync
Chrome;vutbr.cz
WhatsApp;whatsapp
Gmail:mail.google.com
Gmail:inbox.google.com
Facebook:facebook.com
</pre>

For example, by applying keywords on the fingerprint candidates, we select only those fingerprints that are unique and relevant to the app. This is done by the script <tt>ja3db.pl</tt>. 

<tt>Format: ja3db.pl -f \<fingerprint.db\> [-r \<ja3gss.csv\> -k \<keyword\>] -hash \<flag\>] [-p]</tt>
 
Parameters:
* <tt>-f</tt>: SQL database file with fingerprints. It has fixed format: SQL table FingerprintDB with the following columns: JA3hash (text), JA3Shash (text), SNI (text), AppName (text), Flag (text)
* <tt>--r \<ja3gss.csv\> -k \<keyword\> -a \<app name\> -h \<flag\></tt> reads new fingerprints from CSV file and insert them into the DB file. The format of CSV file is JA3 hash; SNI; JA3S hash; filename. The keywoerd is used to select entries from CSV file that matches SNI. The application name will be assigned to the fingerprint in order to identify the mobile app with this fingerprint. The flag describes which items of the fingerprint will be used for identification. The possible values are F (full: Ja3 hash, Ja3s hash, SNI), J (JA3 only), JS (Ja3 hash and Ja3S hash only). 
* <tt>-p</tt> print the entire fingerprints database in CSV format: JA3 hash;JA3S hash;SNI;App name;Flag
 
Example: 
  * <tt>ja3db.pl -f fingerprint.db -r viber-ja3gss.csv  -k viber -hash F -a Viber</tt>
Output:
<pre>
7 item(s) added to the fingerprint database fingerprint.db
</pre>

Example: 
  * <tt>ja3db.pl -f fingerprint.db -p</tt>
Output:
<pre>
JA3 hash;JA3S hash;SNI;App name;Flag
0529055d554c9da011b745452211c296;4e3362a4d6bdc0739bcf48fe32243a69;api.accuweather.com;Accuweather;F
193c522402283ed9e84b8bb38137829f;b63e0ce737c366a59bca6a201d4851ef;accuweather.brightspotcdn.com;Accuweather;F
193c522402283ed9e84b8bb38137829f;0bcfa5ab48fd49e9b452fbea51bf9ff7;api.accuweather.com;Accuweather;F
193c522402283ed9e84b8bb38137829f;4e3362a4d6bdc0739bcf48fe32243a69;api.accuweather.com;Accuweather;F
193c522402283ed9e84b8bb38137829f;70745099b394fe3f42264227c098cc98;cms.accuweather.com;Accuweather;F
193c522402283ed9e84b8bb38137829f;4e3362a4d6bdc0739bcf48fe32243a69;vortex.accuweather.com;Accuweather;F
1d9c09ee8595b0a1e34ac5c212c0448a;7b76ba926d8e1431f720be59188fa170;api.accuweather.com;Accuweather;F
1bff249589c418e6881e847dda91068a;896415616b22361262d7a961b6325cfd;content.cdn.viber.com;Viber;F
73f6df94bdc932425a876de76b538388;0af4105ec22f8e4f02610cf2775dec42;main.crws.cz;Na Vlak;F
</pre>


<h2>Licence</h2>
This software can be freely used under BUT open software licence:
<h3>BUT OPEN SOURCE LICENCE</h3>
Version 1.
Copyright (c) 2017, Brno University of Technology, Antonínská 548/1, 601 90, Czech Republic

BY INSTALLING, COPYING OR OTHER USES OF SOFTWARE YOU ARE DECLARING THAT YOU AGREE WITH THE TERMS AND CONDITIONS OF THIS LICENCE AGREEMENT. IF YOU DO NOT AGREE WITH THE TERMS AND CONDITIONS, DO NOT INSTAL, COPY OR USE THE SOFTWARE.
IF YOU DO NOT POSESS A VALID LICENCE, YOU ARE NOT AUTHORISED TO INSTAL, COPY OR OTHERWISE USE THE SOTWARE.

Definitions:
For the purpose of this agreement, Software shall mean a computer program (a group of computer programs functional as a unit) capable of copyright protection and accompanying documentation.

Work based on Software shall mean a work containing Software or a portion of it, either verbatim or with modifications and/or translated into another language, or a work based on Software. Portions of work not containing a portion of Software or not based on Software are not covered by this definition, if it is capable of independent use and distributed separately.
Source code shall mean all the source code for all modules of Software, plus any associated interface definition files, plus the scripts used to control compilation and installation of the executable program. Source code distributed with Software need not include anything that is normally distributed (in either source or binary form) with the major components (compiler, kernel, and so on) of the operating system on which the executable program runs.

Anyone who uses Software becomes User. User shall abide by this licence agreement.

BRNO UNIVERSITY OF TECHNOLOGY GRANTS TO USER A LICENCE TO USE SOFTWARE ON THE FOLLOWING TERMS AND CONDITIONS:
* User may use Software for any purpose, commercial or non-commercial, without a need to pay any licence fee.
* User may copy and distribute verbatim copies of executable Software with source code as he/she received it, in any medium, provided that User conspicuously and appropriately publishes on each copy an appropriate copyright notice and disclaimer of warranty; keeps intact all the notices that refer to this licence and to the absence of any warranty; and give any other recipients of Software a copy of this licence along with Software. User may charge a fee for the physical act of transferring a copy, and may offer warranty protection in exchange for a fee.
* User may modify his/her copy or copies of Software or any portion of it, thus forming a work based on Software, and copy and distribute such modifications or work, provided that User clearly states this work is modified Software. These modifications or work based on software may be distributed only under the terms of section 2 of this licence agreement, regardless if it is distributed alone or together with other work. Previous sentence does not apply to mere aggregation of another work not based on software with Software (or with a work based on software) on a volume of a storage or distribution medium.
* User shall accompany copies of Software or work based on software in object or executable form with:
a) the complete corresponding machine-readable source code, which must be distributed on a medium customarily used for software interchange; or,
b) written offer, valid for at least three years, to give any third party, for a charge no more than actual cost of physically performing source distribution, a complete machine-readable copy of the corresponding source code, to be distributed on a medium customarily used for software interchange; or,
c) the information User received as to the offer to distribute corresponding source code. (This alternative is allowed only for noncommercial distribution and only if User received the program in objects code or executable form with such an offer, in accord with subsection b above.)
* User may not copy, modify, grant sublicences or distribute Software in any other way than expressly provided for in this licence agreement. Any other copying, modifying, granting of sublicences or distribution of Software is illegal and will automatically result in termination of the rights granted by this licence. This does not affect rights of third parties acquired in good faith, as long as they abide by the terms and conditions of this licence agreement.
* User may not use and/or distribute Software, if he/she cannot satisfy simultaneously obligations under this licence and any other pertinent obligations.
* User is not responsible for enforcing terms of this agreement by third parties.

BECAUSE SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING, BUT PROVIDES SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND,EITHER EXPRESSED OR IMPLIED,INCLUDING,BUT NOT LIMITED TO,THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF SOFTWARE IS WITH USER. SHOULD SOFTWARE PROVE DEFECTIVE, USER SHALL ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL BRNO UNIVERSITY OF TECHNOLOGY BE LIABLE FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF SOFTWARE TO OPERATE WITH ANY OTHER PROGRAMS).

Final provisions:
Any provision of this licence agreement that is prohibited, unenforceable, or not authorized in any jurisdiction shall, as to such jurisdiction, be ineffective to the extent of such prohibition, unenforceability, or non-authorization without invalidating or affecting the remaining provisions.

This licence agreement provides in essentials the same extent of rights as the terms of GNU GPL version 2 and Software fulfils the requirements of Open Source software.

This agreement is governed by law of the Czech Republic. In case of a dispute, the jurisdiction shall be that of courts in the Czech Republic.
By installing, copying or other use of Software User declares he/she has read this terms and conditions, understands them and his/her use of Software is a demonstration of his/her free will absent of any duress.
