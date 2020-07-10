#!/bin/sh

#
# get-ja3s.sh <PCAP> [<OUTPUT DIR>]
#
# Extracts TSL and DNS data from a PCAP file and creates JA3 and JA3S fingerprints
#
# (c) 2020, Petr Matousek, Brno University of Technology
# Project Tarzan
#

# 
# Related Perl scripts
#

DNS2LIST="./dns2list.pl"
TLSS2LIST="./tlss2list.pl"

TSHARK="/usr/local/bin/tshark"

#
# ad-list.txt contains a list of DNS names (each entry per line) of advertisement and tracking servers
# - the list is created by the following resources:
#   https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext&_=3
#   https://hosts-file.net/ad_servers.txt
#   https://gitlab.com/ookangzheng/dbl-oisd-nl/raw/master/dbl.txt
#   https://github.com/lightswitch05/hosts/blob/master/ads-and-tracking-extended.txt
#   https://easylist.to/easylist/easyprivacy.txt
# 
ADLIST="ad-list.txt"

#
# Reading parameters
# 

if [ $# -lt 1 -o $# -gt 3 ]; then
    echo "Usage: $0 <PCAP file> [<output DIR>]"
    exit 1;
fi

if [ ! -r "$1" ]; then
    echo "Cannot read file \"$1\""
    exit 1;
else
    FILENAME=`basename "$1" | cut -d. -f1`
fi

if [ -z $2 ]; then
    if [ ! -d $2 ]; then
	echo "Cannot access output directory  \"$2\""
	exit 1;
    fi
fi

#
# Processing PCAP file
#

INFILE="$1"
OUTDIR="$2"

if [ -z ${OUTDIR} ]; then
    OUTDIR=`dirname "$1"`
fi
echo "Processing file \"${INFILE}\" ..."
echo "Output will be saved into \"${OUTDIR}/\" directory..."

OUTFILE=${FILENAME}-dns.csv

#
# processing DNS responses: only A (type=1) and AAAA (type=28) requests
#

if [ ! -f "${OUTDIR}/${OUTFILE}" ]; then 
    echo "Processing DNS responses over IPv4 ..."
    echo "SrcIP; DstIP; Type; Query; Ans; Auth; Add; Resp. Types; Response; Response Value" > "${OUTDIR}/${OUTFILE}"
          # A request over IPv4
    ${TSHARK} -r "${INFILE}" -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type -e dns.qry.name -e dns.count.answers -e dns.count.auth_rr -e dns.count.add_rr -e dns.resp.type -e dns.resp.name -e dns.a "dns.flags.response eq 1 and ip and dns.qry.type eq 1"  | sort >> "${OUTDIR}/${OUTFILE}"
          # AAAA request over IPv4
    ${TSHARK} -r "${INFILE}" -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type -e dns.qry.name -e dns.count.answers  -e dns.count.auth_rr -e dns.count.add_rr -e dns.resp.type -e dns.resp.name -e dns.aaaa "dns.flags.response eq 1 and ip and dns.qry.type eq 28"  | sort >> "${OUTDIR}/${OUTFILE}"

    echo "Processing DNS responses over IPv6 ..."
          # A request over IPv6
    ${TSHARK} -r "${INFILE}" -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type -e dns.qry.name -e dns.count.answers  -e dns.count.auth_rr -e dns.count.add_rr -e dns.resp.type -e dns.resp.name -e dns.a "dns.flags.response eq 1 and ipv6 and dns.qry.type eq 1"  | sort >> "${OUTDIR}/${OUTFILE}"
          # AAAA request over IPv6
    ${TSHARK} -r "${INFILE}" -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type -e dns.qry.name -e dns.count.answers  -e dns.count.auth_rr -e dns.count.add_rr -e dns.resp.type -e dns.resp.name -e dns.aaaa "dns.flags.response eq 1 and ipv6 and dns.qry.type eq 28"  | sort >> "${OUTDIR}/${OUTFILE}"
fi

#
# printing a full list of resolved entries with AD flag
#
DNSFULL=${FILENAME}-dns-full.csv

if [ ! -f "${OUTDIR}/${DNSFULL}" ]; then
    echo "Saving full DNS output into ${OUTDIR}/${DNSFULL}"
    ${DNS2LIST} -f "${OUTDIR}/${OUTFILE}" -ad > "${OUTDIR}/${DNSFULL}"

    if [ $? -ne 0 ]; then
	echo "Error 2: DNS full list processing failed."
	exit 1;
    fi
fi

#
# printing a short list of resolved entries (IP + hostname) with AD flag
#
DNSLIST=${FILENAME}-dns-list.csv

if [ ! -f "${OUTDIR}/${DNSLIST}" ]; then
    echo "Saving a short DNS list into ${OUTDIR}/${DNSLIST} with Whois resolution ..."
    ${DNS2LIST} -f "${OUTDIR}/${OUTFILE}" -short -ad > "${OUTDIR}/${DNSLIST}"

    if [ $? -ne 0 ]; then
	echo "Error 2: DNS list processing failed."
	exit 1;
    fi 
fi

#
# processing TLS data: if an output file already exists, processing is skipped
#
OUTFILE=${FILENAME}-tlss.csv

if [ ! -f "${OUTDIR}/${OUTFILE}" ]; then 
    echo "Processing TLS traffic ..."
    ${TSHARK} -r "${INFILE}" -T fields -E separator=";" -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite -e tls.handshake.extension.type -e tls.handshake.extensions_server_name -e tls.handshake.extensions_supported_group -e tls.handshake.extensions_ec_point_format -e frame.time -R "tls.handshake.type==1 or tls.handshake.type==2" -2 > "${OUTDIR}/${OUTFILE}" 
    
    if [ $? -ne 0 ]; then
	echo "Error 1: SSL/TLS processing failed."
	exit 1;
    fi
fi
#
# processing TLS handshake and computing JA3 and JA3S fingerprints: full list with GREASE parameter
#
TLSFULLGS=${FILENAME}-tls-fullgs.csv

if [ ! -f "${OUTDIR}/${TLSFULLGS}" ]; then
    echo "Saving full TLS handshakes with JA3 and JA3S hashes into ${OUTDIR}/${TLSFULLG}"
    if [ -s "${OUTDIR}/${DNSLIST}" ]; then  # DNS list file is not empty
	${TLSS2LIST} -f "${OUTDIR}/${OUTFILE}" -dns "$OUTDIR/$DNSLIST" > "${OUTDIR}/${TLSFULLGS}"
    else
	${TLSS2LIST} -f "${OUTDIR}/${OUTFILE}" > "${OUTDIR}/${TLSFULLGS}"
    fi
    
    if [ $? -ne 0 ]; then
	echo "Error 2: TLS full list with JA3 and JA3S processing failed."
	exit 1;
    fi
fi
#
# processing TLS handshake and computing JA3 fingerprints: short list with GREASE
#
TLSLISTGS=${FILENAME}-tls-listgs.csv

if [ ! -f "${OUTDIR}/${TLSLISTGS}" ]; then
    echo "Saving a short list of TLS handshakes with GREASE into ${OUTDIR}/${TLSLISTGS}"
    if [ -s "${OUTDIR}/${DNSLIST}" ]; then
	${TLSS2LIST} -f "${OUTDIR}/${OUTFILE}" -dns "$OUTDIR/$DNSLIST" -list > "${OUTDIR}/${TLSLISTGS}"
    else
	${TLSS2LIST} -f "${OUTDIR}/${OUTFILE}" -list > "${OUTDIR}/${TLSLISTGS}"
    fi
    
    if [ $? -ne 0 ]; then
	echo "Error 2: TLS short list with GREASE processing failed."
	exit 1;
    fi
fi
#
# processing TLS handshake and computing JA3 fingerprints: short list without AD entries with GREASE
#
TLSNOADGS=${FILENAME}-tls-noadgs.csv

if [ ! -f "${OUTDIR}/${TLSNOADGS}" ]; then
    echo "Saving a short list without AD and with GREASE into ${OUTDIR}/${TLSNOADGS}"
    if [ -s "${OUTDIR}/${DNSLIST}" ]; then
	${TLSS2LIST} -f "${OUTDIR}/${OUTFILE}" -dns "$OUTDIR/$DNSLIST" -list -noad > "${OUTDIR}/${TLSNOADGS}"
    else
	${TLSS2LIST} -f "${OUTDIR}/${OUTFILE}" -list -noad > "${OUTDIR}/${TLSNOADGS}"
    fi
    
    if [ $? -ne 0 ]; then
	echo "Error 2: TLS no AD with GREASE processing failed."
	exit 1;
    fi
fi

#
# creates a list of JA3 fingerprints with SNI as CSV file
#
# Output format: Digest;SNI;file-name
#
TLSJA3GSS=${FILENAME}-tls-ja3gss.csv

if [ ! -f "${OUTDIR}/${TLSJA3GSS}" ]; then
    echo "Saving JA3 fingerprints with GREASE and SNI into ${OUTDIR}/${TLSJA3GSS}"
    if [ -s "${OUTDIR}/${TLSNOADGS}" ]; then
	echo "JA3 hash;SNI;JA3S hash;filename" > "${OUTDIR}/$TLSJA3GSS"; 
	cut -d';' -f1,5,6,7 "${OUTDIR}/${TLSNOADGS}" | sort -u | grep -v -E "(JA3|SNI)" >> "${OUTDIR}/${TLSJA3GSS}"
    fi
	
    if [ $? -ne 0 ]; then
	echo "Error 2: TLS no AD with GREASE and SNI processing failed."
	exit 1;
    fi
fi
