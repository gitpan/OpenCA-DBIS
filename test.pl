# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use OpenCA::DBI;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

use OpenCA::OpenSSL;

my $openssl = new OpenCA::OpenSSL;
$openssl->setParams( CONFIG=>"/etc/ssl/openssl.cnf");

# my $db = new OpenCA::DB( SHELL=>openssl, DB_DIR=>"db" );
my $db = new OpenCA::DBI( SHELL=>$openssl, 
                         remoteType => "Pg",
                         remoteHost => "localhost",
                         remotePort => "5432",
                         remoteName => "opencasu",
                         remoteUser => "opencasu",
                         remotePassphrase => "opencasu",
                         failsafe => "off",
                         second_chance => "no",
                         mode => "ultra-secure");

if( not $db ) {
        print "new not ok 1\n";
        exit 1;
}
exit 0;
