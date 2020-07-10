#!/usr/local/bin/perl -w

#
# dns2list.pl: a parser that reads csv output of tshark and processes DNS data
#
# format: dns2list.pl -f input_file [-short] [-ad] [-whois]
#
#       -short: prints only IPv4/6 + domains on the output
#       -ad   : prints AD flag if a domain name is in the list of advertisement servers
#       -whois: requests whois resolution of IP addresses; using whois significantly slows down data processing (!)
#
# input is expected to be a csv file create by following tshark commands:
#       # A responses over IPv4 
#       tshark -r input_file -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type -e dns.qry.name
#              -e dns.count.answers -e dns.count.auth_rr -e dns.count.add_rr
#              -e dns.resp.type -e dns.resp.name -e dns.a
#              "dns.flags.response eq 1 and ip and dns.qry.type eq 1"  | sort 
#       # AAAA request over IPv4
#       tshark -r input_file -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type -e dns.qry.name
#              -e dns.count.answers -e dns.count.auth_rr -e dns.count.add_rr -e dns.resp.type -e dns.resp.name -e dns.aaaa
#              "dns.flags.response eq 1 and ip and dns.qry.type eq 28"  | sort
#       # A request over IPv6
#       tshark -r input_file -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type
#              -e dns.qry.name -e dns.count.answers -e dns.count.auth_rr -e dns.count.add_rr
#              -e dns.resp.type -e dns.resp.name -e dns.a
#              "dns.flags.response eq 1 and ipv6 and dns.qry.type eq 1"  | sort
#       # AAAA request over IPv6
#       tshark -r input file -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type
#              -e dns.qry.name -e dns.count.answers -e dns.count.auth_rr -e dns.count.add_rr
#              -e dns.resp.type -e dns.resp.name -e dns.aaaa
#              "dns.flags.response eq 1 and ipv6 and dns.qry.type eq 28"  | sort
#
# input format: src.ip;dst.ip;dns.type;dns.query;dns.count_answers;dns.count.auth_rr;dns.count.add_rr;
#               dns.types;dns.response;response_value
#         note: dns.response contains one or more domain names related to all sections (ans, auth, add)
#               dns.response_value contains IPv4 or IPv6 addresses related to all sections (ans, auth, add)
#
# ouput format: a list of resolved domain names and IPv4/IPv6 addresses in CSV format
#         domain_name; IPv4/v6 address; ad-server
#
# Date: 9/3/2020
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of TARZAN project (2017-2019)
#
# Last update: 22/4/2020
#
# changes:
#   12/3/2020 - Answer, Authority and Additional counts and sections added for processing
#   22/4/2020 - whois support added using Net::Whois::IP
#   06/5/2020 - whois flag added

use strict;
use Getopt::Long;
#use Net::Whois::ARIN;
use Net::Whois::IP qw(whoisip_query);

#
# global vars
#
my ($dns_db);  # a hash of srcIP addresses and related domain names
my ($keys_db);
my (%adservers);
my ($adlist) = "ad-list.txt";
my ($whois_db);

&Main;

#
# sub Main
#
sub Main {
    my ($filename,$FILE, $ADFILE);
    my ($short) = (0);     # short flag produces a simple output (see above)
    my ($ad) = (0);        # add flag that adds AD to domain names if present in the adlist database
    my ($whois) = (0);     # whois flag - if sets it invokes whois resolution -> returns OrgName to the IP address
    my ($srcIP,$dstIP,$type,$query,$ans,$auth,$add,$types,$response,$value); # single input values
    my (@respt,@resp,@vals);                       # multiple types, responses and values
    my ($row, $i,$j);
    my ($key);
    my ($separator)=";";
    my ($hostname);
    my (@whoisres,$org);   # result of whois query
    
    GetOptions("file=s" => \$filename, "short" => \$short, "ad" => \$ad, "whois" => \$whois);
    
    if (!$filename){
	print "Format: $0 -f <file_name> [-short]\n";
	exit 1;
    }
    if (!open ($FILE,$filename)){
	print "Cannot open file '$filename'\n";
	exit 1;
    }

    if ($ad){
	if (!open ($ADFILE,$adlist)){
	    print "Cannot open file '$adlist' with ad servers\n";
	    exit 1;
	}
	while (<$ADFILE>){        # reading the adfile -> each line contains one domain name
	    $row = $_;
	    $row =~ s/\r//g;      # remove DOS end of line
	    chop($row);
	    $adservers{$row}=1;   
	}
    }

    # reads the CSV-formatted file which is the out of tshark filter (see above)
    while (<$FILE>){
	$row = $_;
	chop($row);
        if ($row  =~ /(.+);(.+);(.+);(.+);(.+);(.+);(.+);(.*);(.*);(.*)/){
	    $srcIP = $1;
	    if ($srcIP eq "SrcIP"){      # skip the title entry
		next;
	    }
	    $dstIP = $2;
	    $type = $3;
	    $query = $4;
	    $ans = $5;
	    $auth = $6;
	    $add = $7;
	    if ($ans == 0){            # no response found -> skip this entry
		next;
	    } elsif ($ans >= 1){         # multiple responses returned -> split the entry
		@respt = split /,/,$8;   # response type array
		@resp = split /,/,$9;    # response name array
		@vals = split /,/,$10;   # response address array (only for type 1 or 28)
		$j = 0;                  # A/AAAA array counter
		for $i (0..$ans-1){
		    if ($respt[$i] == 1 or $respt[$i] == 28){  # only for A or AAAA types
			if ($short){
			    if ($dns_db->{$vals[$j]}){  # value exists
				next;
			    } else {                 # insert a new value
				$dns_db->{$vals[$j]} = $query;
				# $dns_db->{$vals[$j]} = $resp[$i];
			    }
			} else {         # full output
			    if ($ad){    # ad flag set
				if ($adservers{$query}){
				    print $srcIP.$separator.$dstIP.$separator.$type.$separator.$query.$separator.$resp[$i].$separator.$vals[$j].$separator."AD\n";
				} else {
				    print $srcIP.$separator.$dstIP.$separator.$type.$separator.$query.$separator.$resp[$i].$separator.$vals[$j].$separator."\n";
				}
			    }
			    else {       # ad flag not set
				print $srcIP.$separator.$dstIP.$separator.$type.$separator.$query.$separator.$resp[$i].$separator.$vals[$j]."\n";
			    }
			}
			$j++;
		    }
		}
	    }
	} # end if
    } # end while
    #
    #  print the database if $short flag set
    #
    if ($short){
	foreach  $key (sort keys (%{$dns_db})){ # $key is an IPv4 or IPv6 address
	    if ($whois){                        # whois flag is set
		if ($whois_db->{$key}){              # if entry already resolved by whois services
		    $org = $whois_db->{$key};
		}
		else {
		    my $response = whoisip_query($key);
		    if ($response->{'org-name'}){          # Whois output format is variable
			$org = $response->{'org-name'};
		    } elsif ($response->{'OrgName'}){
			$org = $response->{'OrgName'};
		    } elsif ($response->{'Organization'}){
			$org = $response->{'Organization'};
		    } elsif ($response->{'role'}){
			$org = $response->{'role'};
		    } elsif ($response->{'descr'}){
			$org = $response->{'descr'};
		    } elsif ($response->{'netname'}){
			$org = $response->{'netname'};
		    } else {
			$org = "unknown";
		    }
		    $whois_db->{$key} = $org;        # saving the entry
		}
	    } else {
		$org = "not resolved";        # whois resolution switched off
	    }
	    if ($ad){                           # prints AD flag if the hostname is listing in the adfile
		$hostname = $dns_db->{$key};
		if ($adservers{$hostname}) # hostname present
		{
		    print $key.$separator.$org.$separator.$dns_db->{$key}.$separator."AD\n";
		} else {
		    print $key.$separator.$org.$separator.$dns_db->{$key}.$separator."\n";
		}
	    } else {
		print $key.$separator.$org.$separator.$dns_db->{$key}."\n";
	    }
	}
    }
}
