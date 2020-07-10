#!/usr/local/bin/perl -w

#
# ja3db.pl: a script that reads ja3 and ja3s fingerprints and creates ja3 fingerprint database
#                    it also classifies unknown traffic based on the learnt fingerprints
#
# format: ja3db.pl -f <fingerprint.db> [-r <ja3gss.csv> -k <keyword> -a <app name> -hash <flag>] [-c <ja3gss.csv>]
#                                      [-p ]
#
#     -f fingerprint.db ... SQL database file with fingerprints
#            obligatory db format: Table FingerprintDB: JA3hash (text), JA3Shash (text), SNI (text)
#                                                       AppName (text), Flag (text)
#     -r <ja3gss.csv> -k <keyword> -a <app name> -h <flag>... reads new fingerprints from CSV file
#                                                   and insert them into DB file
#                         CSV format: JA3 hash; SNI; JA3S hash; filename
#                         <keyword>: it is used to select entries from CSV file that matches SNI
#                         <app name>: application name that will be assigned to the fingerprint
#                         <flag>: F (full: Ja3 hash, Ja3s hash, SNI), J (JA3 only), JS (Ja3 hash and Ja3S hash only)
#     -c <ja3gss.csv> ... compares fingerprints in CSV with the fingerprinting database
#                         CSV format: JA3 hash; SNI; JA3S hash; filename
#     -p ... print the entire fingerprint database
#
#  ouput: -r ... updated database
#         -c ... JA3 hash; JA3S hash; SNI; App name
#         -p ... JA3 hash; JA3S hash; SNI; App name
#
# Date: 12/5/2020
#
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of TARZAN project (2017-2020)
#
# Updates:
#       13/5/2020 - Flag added
#

use strict;
use Getopt::Long;
use DBI;

#
# global vars
#

my ($fingerprintDB);
my ($TABLE) = ("FingerprintDB");
    
&Main;

#
# sub Main
#
sub Main {
    my ($dbfile);         # fingerprint SQL db file 
    my ($ja3file);        # CSV file with fingerprints for learning
    my ($FILE);           # test filename 
    my ($rflag) = (0);    # reading flag
    my ($cmpfile);        # CSV file for detection
    my ($cflag) = (0);    # comparison flag
    my ($pflag) = (0);    # print SQL db file
    my ($flag) = ("F");   # insertion flag with values F (full), J (Ja3 hash only), JS (Ja3 and ja3s hashes only)
    my ($keyword) = (""); # input keyword (only with -r flag)
    my ($appname) = (""); # input app name (only with -r flag)
    my ($sth);
    my ($delim) = (";");
    my ($ja3,$ja3s,$sni,$row);
    my ($count,$count2,$count3,$i);
    
    GetOptions("file=s" => \$dbfile, "read=s" => \$ja3file, "keyword=s" => \$keyword, "appname=s" => \$appname,  "compare=s" => \$cmpfile, "print" => \$pflag, "hash:s" => \$flag);
    
    if (!$dbfile){
	print "Format: $0 -f <fingerprint.db> [-r <insert-ja3.csv> -k <keyword> -a <app name> -f <flag>] [-c <compare-ja3.csv] [-print] \n";
	exit 1;
    }
    #
    ################## printing fingerprint DB (-p flag) #################
    #
    if ($pflag){     
	print "JA3 hash".$delim."JA3S hash".$delim."SNI".$delim."App name".$delim."Flag\n";
	$pflag = 1;
	if (!open ($FILE,$dbfile)){
	    die ("Cannot open file $dbfile");
	} 
	$fingerprintDB = DBI->connect("dbi:SQLite:dbname=$dbfile","","") or die ("Can't access db file $dbfile");
	$sth = $fingerprintDB->prepare("SELECT * FROM '$TABLE'");
	$sth->execute();
	while ($row = $sth->fetch){
	    print $row->[0].$delim.$row->[1].$delim.$row->[2].$delim.$row->[3].$delim.$row->[4]."\n";
	}
	$sth->finish();
	exit 0;
    } # end if pflag

    #
    ################## comparing fingerprint (-c flag) #################
    #
    if ($cmpfile){ # classifying fingerprints
	$cflag = 1;
	if (!open ($FILE,$dbfile)){
	    die ("Cannot open file $dbfile");
	} 
	$fingerprintDB = DBI->connect("dbi:SQLite:dbname=$dbfile","","") or die ("Can't access db file $dbfile");
	if (!open($FILE,$cmpfile)){
	    print "Cannot open file $cmpfile\n";
	    exit 1;
	}
	while (<$FILE>) # reading a CSV file for classification; format: JA3,SNI,JA3S;filename
	{
	    $row = $_;
	    chop($row);
	    if ($row =~ /(.+);(.*);(.*);(.*)/){    # format: JA3;SNI;JA3S;filename
		$ja3 = $1;
		if ($ja3 eq "JA3 hash"){ # skip CSV header
		    next;
		}
		$sni = $2;
		$ja3s = $3;
		$sth = $fingerprintDB->prepare("SELECT COUNT(*) FROM '$TABLE' WHERE JA3hash = '$ja3' and JA3Shash = '$ja3s' and SNI = '$sni' and Flag = 'F'");
		$sth->execute();
		$count = $sth->fetch;
		if ($count->[0] == 0){         # no fingerprint found on JA3+JA3S+SNI -> try JA3+JA3S only
		    $sth = $fingerprintDB->prepare("SELECT COUNT(*) FROM '$TABLE' WHERE JA3hash = '$ja3' and JA3Shash = '$ja3s' and Flag = 'JS'");
		    $sth->execute();
		    $count2 = $sth->fetch;
		    if ($count2->[0] == 0){    # no match found on JA3+JA3S -> try JA3 only
			$sth = $fingerprintDB->prepare("SELECT COUNT(*) FROM '$TABLE' WHERE JA3hash = '$ja3' and Flag = 'J'");
			$sth->execute();
			$count3 = $sth->fetch;
			if ($count3->[0] == 0){       # no match found on JA3 only
			    print $ja3.$delim.$ja3s.$delim.$sni.$delim."* unknown app\n";
			} elsif ($count3->[0] == 1){  # one entry found on JA3 only
			    $sth = $fingerprintDB->prepare("SELECT AppName FROM '$TABLE' WHERE JA3hash = '$ja3' and Flag = 'J'");
			    $sth->execute();
			    $row = $sth->fetch;
			    print $ja3.$delim."".$delim."".$delim.$row->[0]."\n";
			} else {                      # multiple matches on JA3 only
			    print $ja3.$delim."".$delim."".$delim."** multiple matches\n";
   			}
			
		    } elsif ($count2->[0] == 1){ # one match on JA3 and JA3S 
			$sth = $fingerprintDB->prepare("SELECT AppName FROM '$TABLE' WHERE JA3hash = '$ja3' and JA3Shash = '$ja3s' and Flag = 'JS'");
			$sth->execute();
			$row = $sth->fetch;
			print $ja3.$delim.$ja3s.$delim."".$delim.$row->[0]."\n";
		    } else {                    # multiple matches on JA3 and JA3S 
			print $ja3.$delim.$ja3s.$delim.$sni.$delim."** multiple matches\n";
		    }
		} elsif ($count->[0] == 1){  # one match on JA3+JA3S+SNI    
		    $sth = $fingerprintDB->prepare("SELECT AppName FROM '$TABLE' WHERE JA3hash = '$ja3' and JA3Shash = '$ja3s' and SNI = '$sni' and Flag = 'F'");
		    $sth->execute();
		    $row = $sth->fetch;
		    print $ja3.$delim.$ja3s.$delim.$sni.$delim.$row->[0]."\n";
		} else {                     # multiple matches on JA3+JA3S+SNI
		    print $ja3.$delim.$ja3s.$delim.$sni.$delim."** multiple matches\n";
		}
	    }  # end if =~ //
	}  # end while
	exit 0;  # exit cmpfile section
    } # end if $cmpfile

    #
    ################## adding new fingerprint(s) (-a flag) #################
    #
    if ($ja3file){  # reading new fingerprints from a file and storing them into SQL database
	if (($keyword eq "") || ($appname eq "")){
	    print "Format: $0 -f <fingerprint.db> [-r <insert-ja3.csv> -k <keyword> -a <app name>] [-c <compare-ja3.csv] [-print] \n";
	    exit 1;
	} else {
	    $rflag = 1;
	    $i = 0;     # number of inserted entries
	    $fingerprintDB = DBI->connect("dbi:SQLite:dbname=$dbfile","","") or die ("Can't access db file $dbfile");
	    if (!open($FILE,$ja3file)){
		print "Cannot open file $ja3file\n";
		exit 1;
	    }
	    while (<$FILE>){
		$row = $_;
		chop($row);
		if ($row =~ /(.+);(.*);(.*);(.*)/){    # format: JA3;SNI;JA3S;filename
		    $ja3 = $1;
		    $sni = $2;
		    $ja3s = $3;
		    if ($ja3s eq ""){                  # skip entries with incomplete data (only TLS Client Hello)
			next;
		    }
		    if ($sni =~ /$keyword/){
			if ($flag eq "F"){
			    $sth = $fingerprintDB->prepare("SELECT COUNT(*) FROM '$TABLE' WHERE JA3hash = '$ja3' and JA3Shash = '$ja3s' and SNI = '$sni' and AppName = '$appname' and Flag = 'F'");
			} elsif ($flag eq "JS"){
			    $sth = $fingerprintDB->prepare("SELECT COUNT(*) FROM '$TABLE' WHERE JA3hash = '$ja3' and JA3Shash = '$ja3s' and AppName = '$appname' and Flag = 'JS'");
			} else {
			    $sth = $fingerprintDB->prepare("SELECT COUNT(*) FROM '$TABLE' WHERE JA3hash = '$ja3' and AppName = '$appname' and Flag = 'J'");
			}
			$sth->execute();
			$count = $sth->fetch;
			if ($count->[0] == 0){   # entry not present in the database
			    if ($flag eq "F"){
				$sth = $fingerprintDB->prepare("INSERT INTO '$TABLE' ('JA3hash','JA3Shash','SNI','AppName','Flag') VALUES ('$ja3','$ja3s','$sni','$appname','F')");
				$i++;
			    } elsif ($flag eq "JS"){
				$sth = $fingerprintDB->prepare("INSERT INTO '$TABLE' ('JA3hash','JA3Shash','SNI','AppName','Flag') VALUES ('$ja3','$ja3s','','$appname','JS')");
				$i++;
			    } else {
				$sth = $fingerprintDB->prepare("INSERT INTO '$TABLE' ('JA3hash','JA3Shash','SNI','AppName','Flag') VALUES ('$ja3','','','$appname','J')");
				$i++;  
			    }
			    $sth->execute();
			}
		    } # end if sni
		} # end if =~ //
	    } # end while
	    $sth->finish();
	    print "$i item(s) added to the fingerprint database $dbfile\n";
	    exit 0;
	} # end if keyword + appname
    } # end if ja3file

    if ((!$pflag) || (!$rflag) || (!$cflag)){ # if a flag is missing
	print "Format: $0 -f <fingerprint.db> [-r <insert-ja3.csv> -k <keyword> -a <app name>] [-c <compare-ja3.csv] [-print] \n";
	exit 1;
    }
} # end of main
