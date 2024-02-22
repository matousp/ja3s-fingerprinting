#!/usr/local/bin/perl -w

#
# tlss2list.pl: a parser that reads csv output of the tshark, processes TLS handshakes and computes JA3 and JA3S hashes
#              it also excludes GREASE values from fingerprinting by default, see RFC 8701, and renegotiation, see RFC 5746
#
# format: tlss2list.pl -f input_file [-dns dns_file] [-list] [-noad]
#
#             -dns: dns file with resolved IP addresses and AD flags
#                   CSV format: IPv4/IPv6 address;whois orgname; domain name;AD flag,
#                               duplicated entries are present
#
#             -list: simple ouput: IP address + fingerprint + AD flag, only unique entries
#
#             -noad: an output without entries with AD flag
# 
# input is expected to be tshark output:
#     # tshark -r <PCAP file> -T fields -E separator=";" -e ip.src -e ip.dst -e tcp.srcport 
#              -e tcp.dstport -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite
#              -e tls.handshake.extension.type -e tls.handshake.extensions_server_name
#              -e tls.handshake.extensions_supported_group
#              -e tls.handshake.extensions_ec_point_format
#              -e frame.number -R "ssl.handshake.type==1" -2 
#              | sort -u
# 
#     input format: SrcIP;DstIP;Handshake Type;SSL version;CipherSuite;Extensions;SNI;
#                   SupportedGroups;EC_point_format;Timestamp
#
#  full ouput:    srcIP;dstIP;srcPort,dstPort;OrgNam;SNI;hostname;AD flag;version;client ciphersuite;
#                 client extensions;client supported_groups;client ec_format;JA3 hash;
#                 server ciphersuite;server extensions;server supported_groups;server ec_format;JA3S hash
#  simple output: srcIP, dstIP, fingerprint, domain name, AD flag
#       
#
# Date: 7/5/2020
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of TARZAN project (2017-2020)
#
# Changes:
#   22/2/2024: hex values converted to dec values to be compatible with the standard JA3 fingerprint (as used in Wireshark)
#              renegotiation and padding extensions not excluded from the extension list for compatibility with the standard JA3
#

use strict;
use Getopt::Long;
use Digest::MD5 qw(md5 md5_hex md5_base64);

#
# global vars
#
my ($delim) = ";";
my (%dns_db);   # a hash array of resolved IP addresses with AD flag
my (%tls_db);   # a hash array of all processed TLS handshakes
my (%short_db); # a hash array of unique entries of the short list

&Main;

#
# sub Main
#
sub Main {
    my ($filename,$dnsfile,$FILE,$DNSFILE,$noad);
    my ($srcIP,$dstIP,$srcPort,$dstPort,$type,$version,$cipher_suite,$sni,$supported_groups,$extensions,$ec_format);
    my ($orgName,$AD_flag,$hostname,$type1);
    my ($row,$key,$entry,$cipher_suite_dec);
    my ($ja3,$ja3s);
    my ($list) = (0);
    my (@groups, $sg, $i, @suites);
    my (@GREASE_HEX) = (0x0A0A,0x1A1A,0x2A2A,0x3A3A,0x4A4A,0x5A5A,0x6A6A,0x7A7A,0x8A8A,0x9A9A,0xAAAA,0xBABA,0xCACA,0xDADA,0xEAEA,0xFAFA);
    my (@GREASE) = (2570,6682,10794,14906,19018,23130,27242,31354,35466,39578,43690,47802,51914,56026,60138,64250); #,65281);
    my ($padding) = (21);  
    GetOptions("file=s" => \$filename, "list" => \$list, "dns=s" => \$dnsfile, "noad" => \$noad);
    
    if (!$filename){
	print "Format: $0 -f <file_name> [-dns <dns_file>] [-list] [-noad]\n";
	exit 1;
    }
    if (!open ($FILE,$filename)){
	print "Cannot open file '$filename'\n";
	exit 1;
    }
    #
    # reads DNS names and IP addresses in CSV format: IP address;domain name; AD flag
    #
    if ($dnsfile){
	if (!open ($DNSFILE,$dnsfile)){
	    print "Cannot open DNS file '$dnsfile'\n";
	    exit 1;
	}
	while (<$DNSFILE>){
	    $row = $_;
	    chop($row);
	    if ($row =~ /(.+);(.+);(.+);(.*)/){
		$dns_db{$1}[0] = $3;        # dns_db{IP address} [0] = domain name
		$dns_db{$1}[1] = $4;        # dns_db{IP address} [1] = AD flag
		$dns_db{$1}[2] = $2;        # dns_db{IP address} [2] = org name
	    }
	}
    }
    # reads the CSV-formatted file which is the out of tshark filter (see above)
    while (<$FILE>){
	$row = $_;
	chop($row);
        if ($row  =~ /(.+);(.+);(.+);(.+);(.+);(.+);(.+);(.+);(.*);(.*);(.*);(.*)/){
	    $srcIP = $1;
	    $dstIP = $2;
	    $srcPort = $3;
	    $dstPort = $4;
	    $type = $5;
	    @groups = split /\,/,$5;     # if Server Hello with additional parts in one packet
	    $type = $groups[0];          # the first value is correct
	    $version = hex($6);
	    $cipher_suite = $7;
	    @suites = split /\,/,$cipher_suite;        # convert cipher_suites from hex to decimal format
	    $cipher_suite_dec = "";
	    foreach $i (@suites){                   
		if ($cipher_suite_dec eq ""){
		    $cipher_suite_dec = hex($i);
		}
		else
		{
		    $cipher_suite_dec = $cipher_suite_dec."-".hex($i);
		}
	    }
	    $extensions = $8;
	    $sni = $9;
	    $supported_groups = $10;
	    $ec_format = $11;
#	    $cipher_suite =~ s/\,/\-/g;             # substitute separators to form a JA3 fingerprint
	    $extensions =~ s/\,/\-/g;
	    foreach $i (@GREASE){                   # exclude GREASE values from cipher suit and extensions
		$cipher_suite_dec =~ s/$i-//g;
		$extensions =~ s/$i-//g;
		$cipher_suite_dec =~ s/-$i//g;
		$extensions =~ s/-$i//g;
	    }
#	    $extensions =~ s/21-//g;                # exclude padding extension (21), see RFC 7685
#	    $extensions =~ s/-21//g; 
	    @groups = split /\,/,$supported_groups; # convert supported groups from hex to dec
	    $sg="";
	    foreach $i (@groups){
		if ($sg eq ""){
		    $sg = hex($i);
		} else {
		    $sg=$sg."-".hex($i);
		}
	    }
	    foreach $i (@GREASE){               # exclude GREASE values from supported groups
		$sg =~ s/$i-//g;                
		$sg =~ s/-$i//g; 
	    }
	    #
	    # compute JA3 and JA3S hashes
	    #
	    $hostname = "";
	    $AD_flag = "";
	    $orgName = "";
	    if ($type == 1){          # Client Hello
		$key = $srcIP.":".$dstIP.":".$srcPort;  # compute a hash key for %tls_db
		$ja3 = md5_hex($version.",".$cipher_suite_dec.",".$extensions.",".$sg.",".$ec_format);
		if ($dnsfile){        # DNS responses are available 
		    if ($dns_db{$dstIP}){         # Dst IP can be resolved
			$hostname = $dns_db{$dstIP}[0];
			$AD_flag = $dns_db{$dstIP}[1];
			$orgName = $dns_db{$dstIP}[2];
		    }
		}
		# create a new entry
		if ($list){    # short output
		    if ($noad){    # skip if AD flag is set
			if ($AD_flag ne "AD"){
			    $entry = $ja3.$delim.$srcIP.$delim.$dstIP.$delim.$orgName.$delim.$sni;
			} else {
			    next;
			}
		    } else {
			$entry = $srcIP.$delim.$dstIP.$delim.$orgName.$delim.$sni.$delim.$AD_flag.$delim.$ja3;
		    }
		} else {       # full output
		    if ($noad){
			if ($AD_flag ne "AD"){
			    $entry = $ja3.$delim.$srcIP.$delim.$dstIP.$delim.$srcPort.$delim.$dstPort.$delim.$orgName.$delim.$sni.$delim.$hostname.$delim.$version.$delim.$cipher_suite_dec.$delim.$extensions.$delim.$supported_groups.$delim.$ec_format;
			} else {
			    next;
			}
		    } else {
			$entry = $srcIP.$delim.$dstIP.$delim.$srcPort.$delim.$dstPort.$delim.$orgName.$delim.$sni.$delim.$hostname.$delim.$AD_flag.$delim.$version.$delim.$cipher_suite_dec.$delim.$extensions.$delim.$supported_groups.$delim.$ec_format.$delim.$ja3;
		    }
		}
		# insert a new entry into tls hash array
		$tls_db{$key} = $entry;    
	    }
	    else {                    # Server Hello
		$ja3s = md5_hex($version.",".$cipher_suite_dec.",".$extensions);
		$key = $dstIP.":".$srcIP.":".$dstPort;  # compute a hash key for %tls_db
		if ($tls_db{$key}){   # if a Client Hello exists in the db
		    $entry = $tls_db{$key};
		                      # add Server Hello data to the entry
		    if ($list){       # short output
			if ($noad){
			    $tls_db{$key} = $entry.$delim.$ja3s.$delim.$filename;
			} else {
			    $tls_db{$key} = $entry.$delim.$ja3s;
			}
		    } else {          # full output
			if ($noad){
			    $tls_db{$key} = $entry.$delim.$ja3s.$delim.$cipher_suite_dec.$delim.$extensions.$delim.$supported_groups.$delim.$ec_format;
			} else {
			    $tls_db{$key} = $entry.$delim.$cipher_suite_dec.$delim.$extensions.$delim.$supported_groups.$delim.$ec_format.$delim.$ja3s;
			}
		    }
		}
	    }
	    
	} # end if 
    } # end of input reading (while loop)
    #
    # print the output
    #
    if ($list){
	if ($noad){ # noad file
	    print "JA3 hash".$delim."SrcIP".$delim."DstIP".$delim."OrgName".$delim."SNI".$delim."JA3S hash".$delim."Filename\n";
	} else {    # list file
	    print "SrcIP".$delim."DstIP".$delim."OrgName".$delim."SNI".$delim."AD flag".$delim."JA3 hash".$delim."JA3S hash\n";
	}
	foreach $key (sort keys %tls_db){
	    print $tls_db{$key}."\n";
	}
    } else {       # full list
	if ($noad){
	    print "JA3 hash".$delim."SrcIP".$delim."DstIP".$delim."SrcPort".$delim."DstPort".$delim."OrgName".$delim."SNI".$delim."Hostname".$delim."Version".$delim."Client CipherSuite".$delim."Client Extensions".$delim."Client SG".$delim."CEC_fmt".$delim."JA3hash".$delim."Server CipherSuite".$delim."Server Extensions".$delim."Server SG".$delim."SEC_fmt\n";
	} else {
	    print "SrcIP".$delim."DstIP".$delim."SrcPort".$delim."DstPort".$delim."OrgName".$delim."SNI".$delim."Hostname".$delim."AD flag".$delim."Version".$delim."Client CipherSuite".$delim."Client Extensions".$delim."Client SG".$delim."CEC_fmt".$delim."JA3hash".$delim."Server CipherSuite".$delim."Server Extensions".$delim."Server SG".$delim."SEC_fmt".$delim."JA3S hash\n";		
	}
	foreach $key (sort keys %tls_db){
	    print $tls_db{$key}."\n";
	}
    }
} # end main
