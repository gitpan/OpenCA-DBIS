#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DBI;
use OpenCA::DBIS;

my $openssl = new OpenCA::OpenSSL;
my @tmpfiles = ("cert.pem","priv.key","req.pem");

print "Initializing crypto shell ... \n";
$openssl->setParams ( SHELL=>"/usr/bin/openssl",
		      CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf" );
		      # CONFIG=>"/etc/ssl/openssl.cnf" );

$openssl->setParams ( STDERR => "/dev/null" );

print "Generating a 512 bit priv Key ...\n";
if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key" ) ) {
 	print "Error\n";
}

print "Generating a Request file ... \n";
$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
 		DN=>["", "", "", "CA", "", "Massimiliano Pala", "madwolf\@openca.org", "", "" ] );

print "Generating a CA certificate ... \n";
$p = $openssl->genCert( KEYFILE=>"priv.key", REQFILE=>"req.pem", DAYS=>150,
			OUTFILE=>"cert.pem");

############################
## new for OpenCA::DBIS
###########################

## $dbis1 = new OpenCA::DBIS (DEBUG     => 0,
##                           SHELL     => $openssl,
##                           IPC_USER  => "michael",
##                           IPC_GROUP => "michael",
## 			  CERT_FILE => "cert.pem",
##                           KEY_FILE  => "priv.key");

## print "new OpenCA::DBIS failed\n" if (not $dbis1);

## print "init OpenCA::DBIS signing daemon\n";

## if (($error = $dbis1->startSigningDaemon ()) < 0) {
##   print "error on startup of signing daemon detected by prova.pl\n";
##   print "errorcode: ".$error."\n";
## }

##exit;

$dbis2 = new OpenCA::DBIS (DEBUG     => 0,
                           SHELL     => $openssl);

$data = "Ich bitte um eine Signatur ;-)!\n";
print "try to sign:\n";
print "begin of data\n";
print $data;
print "end of data\n";
my ($cert, $data) = $dbis2->getSignature (DATA => $data);
print "signature\n".$data."\n";
print "cert\n".$cert."\n";

## if (($error = $dbis2->stopSigningDaemon ()) < 0) {
##   print "error on stop of signing daemon detected by prova.pl\n";
##   print "errorcode: ".$error."\n";
## } else {
##   print "Daemon stopped\n";
## }

print "test finished\n";

exit;

############################
## new for OpenCA::DBIS
###########################

my $X509 = new OpenCA::X509( INFILE=>"cert.pem",
			     FORMAT=>"PEM", SHELL=>$openssl);

print " * Serial: " . $X509->getParsed()->{SERIAL} . "\n";
print " * Version: " . $X509->getParsed()->{VERSION} . "\n";
print " * Modulus: " . $X509->getParsed()->{MODULUS} . "\n";
print " * Exponent: " . $X509->getParsed()->{EXPONENT} . "\n";

print "Creating a new CRL Object ... \n";
my $CC = new OpenCA::CRL( SHELL=>$openssl, 
                          CACERT=>"cert.pem",
			  CAKEY=>"priv.key", 
                          PASSWD => "");
if( not $CC ) {
	print "Error!\n";
}

# my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );
my $db = new OpenCA::DBI( SHELL=>$openssl, 
                         remoteType => "Pg",
                         remoteHost => "192.168.1.3",
                         remotePort => "5432",
                         remoteName => "opencasu",
                         remoteUser => "opencasu",
                         remotePasswd => "opencasu",
                         failsafe => "off",
                         second_chance => "no",
                         mode => "ultra-secure");

if( not $db ) {
        print "new not ok\n";
        exit 1;
}

print "My class initializes correctly!\n";

$rv = $db->initDB (MODE=> "FORCE_ALL");
if ($rv < 0) {
        print "initDB returns negative\n";
}

print "Storing Request ... \n";
my $r = new OpenCA::REQ( SHELL   => $openssl, 
                         FORMAT  => "PEM", 
                         INFILE  => "req.pem",
 		         DN      => ["", "", "", "CA", "", 
                                     "Massimiliano Pala", 
                                     "madwolf\@openca.org", "", "" ],
                         KEYFILE => "priv.key" );
if (not $r) {
	print "new OpenCA::REQ failed\n";
       	exit 1;
}

$rv = $db->storeItem( DATATYPE=>PENDING_REQUEST, OBJECT=>$r,
                      CERT_FILE=>"cert.pem", KEY_FILE=>"priv.key", PWD=>"" );

if( (not $rv ) or ($rv < 0)) {
  	print "13 ....... not ok 13\n";
   	exit 1;
}

print "storeItem is ok!\n";

print "Storing CRL to DB ....\n";
if (not $CC) {
	print "there is no CRL\n";
} else {
	if( not $db->storeItem( DATATYPE=>CRL, OBJECT=>$CC, 
                                CERT_FILE=>"cert.pem", KEY_FILE=>"priv.key", PWD=>"" ) ) {
   		print "14 ....... not ok 14\n";
	}
}

print "rest is senseless because genCRL don't works\n" if (not $CC);

## print "Retrieving the CRL from the DB ... \n";
## @list = $db->searchItem( DATATYPE=>CRL, LAST_UPDATE=>"Feb 16 12:18" );
 
## my $testDate = "May 10 10:25:32 2000";
## my $testDate = "Sun Apr 30 23:05:38 2000 GMT";
 
## @list = $db->searchItem( DATATYPE=>CRL, DATE=>$testDate );

print "searching for DATATYPE=>CRL ...\n";
@list = $db->searchItem( DATATYPE=>CRL );

print "try to get elements and rows\n"; 
$total    = $db->elements( DATATYPE=>CRL );
print "elements return: ".$total."\n";
## $elements = $db->rows( DATATYPE=>CRL, DATE=>$testDate );
$elements = $db->rows( DATATYPE=>CRL );
print "rows return: ".$elements."\n";
 
print "Retrieved $elements on $total elements ...\n";
print "this doesn't work ... and it's absolut frustrating to don't know why\n";
foreach $crl (@list) {
	print "this item ist not a crl-object or something else\n" if (not $crl);
        print "\n";
        print " * dB Key:      ".$crl->{KEY}."\n";
        print " * Version:     " . $crl->{VALUE}->getParsed()->{VERSION} . "\n";
        print " * Type:        " . $crl->{DATATYPE} . "\n";
        print " * Last Update: ".$crl->{VALUE}->getParsed()->{LAST_UPDATE}."\n";
        print " * Next Update: ".$crl->{VALUE}->getParsed()->{NEXT_UPDATE}."\n";
        print "\n";
}
 
## @list = $db->searchItem( DATATYPE=>REQUEST );
## $elements = $db->elements( DATATYPE=>REQUEST );
                                                                                              
## print "Retrieved $elements elements ...\n";
## foreach $crl (@list) {
##      print "\n";
##      print " * dB Key:      $crl->{KEY}\n";
##      print " * Type:        " . $crl->{DATATYPE} . "\n";
##      print " * Version:     " . $crl->{VALUE}->getParsed()->{VERSION} . "\n";
##      print " * CN:          ".$crl->{VALUE}->getParsed()->{CN}."\n";
##      print " * Modulus:     ".$crl->{VALUE}->getParsed()->{MODULUS}."\n";
##      print " * Approved:    ".$crl->{VALUE}->getParsed()->{APPROVED}."\n";
##      print "\n";
## }
 
print "Unlinking temp files ... \n";
 
foreach $tmp (@tmpfiles) {
        unlink( "$tmp" );
}
 
print "Ok.\n\n";
 
print "dB Status:\n\n";
 
print "STATUS   => " . $db->getItem( DATATYPE =>CRL, KEY=>STATUS ) . "\n";
print "INIT     => " . $db->getItem( DATATYPE =>CRL, KEY=>INIT ) . "\n";
print "MODIFIED => " . $db->getItem( DATATYPE =>CRL, KEY=>MODIFIED ) . "\n";
print "DELETED  => " . $db->getItem( DATATYPE =>CRL, KEY=>DELETED ) . "\n";
print "ELEMENTS => " . $db->elements( DATATYPE => CRL ) . "\n";
print "SERIAL   => " . $db->getSerial( DATATYPE => CRL ) . "\n\n";
 
exit 0;                                                                                      
