## OpenCA::DBIS
##
## Copyright (C) 2000-2001 Michael Bell (michael.bell@web.de)
##
## GNU Public License Version 2
##
## see file LICENSE or contact
##   Free Software Foundation, Inc.
##   675 Mass Ave, Cambridge, MA 02139, USA
##

use strict;

package OpenCA::DBIS;

use OpenCA::REQ;   ## why ?
use OpenCA::X509;  ## why ?
use OpenCA::CRL;   ## why ?
use OpenCA::CRR;   ## why ?
use OpenCA::OpenSSL;
use OpenCA::Tools; ## why ?
use DBI;           ## why ?
use English;
use POSIX;
use IPC::SysV;
use IPC::SysV qw (IPC_RMID IPC_CREAT);

## the other use directions depends from the used databases
## $Revision: 0.1.1.2 

$OpenCA::DBIS::VERSION = '0.2.0';

$OpenCA::DBIS::ERROR = {
                       SETUID_FAILED       => -101,
                       SETGID_FAILED       => -102,
                       MKFIFO_FAILED       => -103,
                       OPEN_FIFO_FAILED    => -104,
                       OPEN_PIDFILE_FAILED => -105,
                       MISSING_CERT_FILE   => -106,
                       MISSING_KEY_FILE    => -107,
                       FORK_FAILED         => -108,
                       MSGGET_FAILED       => -109,
                       MSGRCV_FAILED       => -110,
                      };

## Hit it in your phone if don't know what does this key mean ;-D
# $OpenCA::DBIS::MESSAGEKEY = 6736223247; too long
$OpenCA::DBIS::MESSAGEKEY = 673622324;
$OpenCA::DBIS::MESSAGELENGTH = 256;
$OpenCA::DBIS::LOGSECURITY = 0;
$OpenCA::DBIS::LOGPERFORMANCE = 8;

my $params = {
	      backend       => undef,
              CERT_FILE     => undef,
              KEY_FILE      => undef,
              PASSWD           => undef,
              # MESSAGEKEY    => "openca_signing_daemon",
              ## perl doesn't support ftok - what is this true ?!!!!!
              ## never run as other user or group 
              MESSAGEKEY    => $OpenCA::DBIS::MESSAGEKEY,
              MESSAGELENGTH => $OpenCA::DBIS::MESSAGELENGTH,
              PIDFILE       => "/var/run/openca_signing_daemon.pid",
              LOGFILE       => "/var/log/openca_signing_daemon.log",
              IPC_USER      => undef,
              IPC_GROUP     => undef,
              IPC_UID       => undef,
              IPC_GID       => undef,
              tools         => undef,
              DEBUG         => 0
	     };

sub new { 
  
  # no idea what this should do
  
  my $that  = shift;
  my $class = ref($that) || $that;
  
  ## my $self  = $params;
  my $self;
  my $help;
  foreach $help (keys %{$params}) {
    $self->{$help} = $params->{$help};
  }
   
  bless $self, $class;

  # ok here I start ;-)

  $self->init (@_);

  return $self;
}

sub startSigningDaemon {
  ## special thanks to my father for the excellent lecture
  ## Unix systemarchitecture and systeminterface (you can
  ## listen it at Humboldt-University of Berlin's institute
  ## of computer science ;-)
  ##
  ## I thought I would never need System V/BSD IPC except of
  ## sockets

  my $self = shift;
  my $keys = { @_ };
 
  $self->init (@_);
 
  ## check for actual user and group
  ## change to predefined user and group if necessary
  print "    try to set UID and GID if necessary\n" if ($self->{DEBUG});
  if ($UID != $self->{IPC_UID}) {
    ## try to set correct uid
    if (POSIX::setuid ($self->{IPC_UID}) < 0) {
      return $OpenCA::DBIS::ERROR->{SETUID_FAILED};
    }
  }
  print "  IPC_UID: ".$self->{IPC_UID}."\n  UID: ".POSIX::getuid ()."\n" if ($self->{DEBUG});
  if ($GID != $self->{IPC_GID}) {
    ## try to set correct uid
    if (POSIX::setgid ($self->{IPC_GID}) < 0) {
      return $OpenCA::DBIS::ERROR->{SETGID_FAILED};
    }
  }
  print "  IPC_GID: ".$self->{IPC_GID}."\n  GID: ".POSIX::getgid ()."\n" if ($self->{DEBUG});
 
  ## ok I need a cert and a key at minimum
  print "    check for cert and key at minimum\n" if ($self->{DEBUG});
  return $OpenCA::DBIS::ERROR->{MISSING_CERT_FILE} if (not $self->{CERT_FILE});
  return $OpenCA::DBIS::ERROR->{MISSING_KEY_FILE}  if (not $self->{KEY_FILE});

  print "  initialization complete except of msgget\n" if ($self->{DEBUG});

  ## create messageQueue
  print " MESSAGEKEY: ".$self->{MESSAGEKEY}."\n" if ($self->{DEBUG});
  my $msgid = msgget ($self->{MESSAGEKEY}, IPC_CREAT | S_IRUSR | S_IWUSR);
  return $OpenCA::DBIS::ERROR->{MSGGET_FAILED} if (not $msgid);

  print "msgid: ".$msgid."\n" if ($self->{DEBUG});

  print "  initialization complete\n" if ($self->{DEBUG});

  ## fork away for real operation
  my $pid;
  if ($pid = fork ()) {
    
    ## parent finish

    ## preparations to kill the daemon
    print "try to open PIDFILE ...\n" if ($self->{DEBUG});
    if (not open (PIDFILE, ">".$self->{PIDFILE})) {
      my $warning = "WARNING: cannot write pidfile \"".$self->{PIDFILE}."\"\n".
                    "         sub stopSigningDaemon doesn't work!\n";
      print STDOUT $warning;
      $self->doLog ($warning);
    } else {
      print "PID:".$pid."\n" if ($self->{DEBUG}); 
      print PIDFILE sprintf ("%d", $pid);
      close PIDFILE;
    }

    ## print to LOGFILE the startup
    $self->doLog ("startSigningDaemon successfull at ".
           gmtime ()." PID: ".sprintf ("%d", $pid)."\n");
    
    ## all ok
    return 0;
    
  } elsif (defined $pid) {
    
    ## child
    my $cpid;
    
    ## undock from parent process
    ## I think $$ is in perl getpid but I'm not shure ...
    setpgrp (0, $PID);
    
  IPCLOOP: while (1) {
      
      ## read length until \n
      my $fifo;
      my $tmpfifoIn = "";

      print "IPCLOOP waits for message\n" if ($self->{DEBUG}); 
      if (not msgrcv ($msgid, $tmpfifoIn, $self->{MESSAGELENGTH}, 0, 0)) {
        $self->doLog ("msgrcv failed, daemon softly killed\n");
        exit;
      }
      (undef, $tmpfifoIn) = unpack ("L a*", $tmpfifoIn);
      print "IPCLOOP has a message: \"".$tmpfifoIn."\"\n" if ($self->{DEBUG}); 

      ## fork away
      if ($cpid = fork ()) {
        ## all ok continue working
        ## continue reading from FIFO in blocking mode
        next IPCLOOP;
      } elsif (defined $cpid) {
        ## child
        ## ok continue
      } else {
        ## shit fork failed
        
        ## try to handle request in one process
        $self->doLog ("WARNING: fork of the OpenCA::DBIS signing daemon failed\n".
                      "         continue working but slow down\n");
      }
      
      ## this is only reached if it is a child or fork failed

      my ($answer_fifo, $data) = $self->getData ($tmpfifoIn);
      die if (($answer_fifo eq "") and (defined $cpid));
      next IPCLOOP if ($answer_fifo eq "");
      
      ## sign data
      my $signdata;
      if ($data) {

        ## is this now an array for getSigndata or not?
        print "    enter getSigndata\n" if ($self->{DEBUG});
        $signdata = OpenCA::DBIS->getSigndata (CERT_FILE => $self->{CERT_FILE},
                                               KEY_FILE  => $self->{KEY_FILE},
                                               PASSWD    => $self->{PASSWD},
                                               SHELL     => $self->{backend},
                                               DATA      => $data);
        print "    returning from getSigndata\n" if ($self->{DEBUG});
     
        if (not $signdata) {
          $signdata = "";
        }
      } else {
        $signdata = "";
      }
 
      ## store length
      my $load = sprintf ("%d", length($self->{CERT_FILE}))."\n";

      ## store cert
      $load .= $self->{CERT_FILE};    
 
      ## store length
      $load .= sprintf ("%d", length($signdata))."\n";
      
      ## store signature
      $load .= $signdata;
      
      ## open answer pipe
      if (not open (ANSWERFIFO, ">".$answer_fifo)) {
        ## hui cannot open answer fifo
        ## rising alert message
        $self->doLog ("WARNING: OpenCA::DBIS signing daemon cannot open answerfifo\n".
                      "         this could be an attack or an killed http-request!\n".
                      "         please verify this\n");
        ## exit
        die if (defined $cpid);
        next IPCLOOP;
      }
      
      ## write load
      print ANSWERFIFO $load;
      
      ## close answer pipe
      close ANSWERFIFO;
      
      ## exit if forked child
      die if (defined $cpid);
        
      ## automatic next FIFOLOOP if failed fork
      
    } ## end of while (1) loop
  } else {
    print "OpenCA::DBIS signing daemon cannot fork so startup failed\n";
    ## print to LOGFILE the startup

    $self->doLog ("startSigningDaemon failed at ".
           gmtime ()." PID: ".sprintf ("%d", $pid)."\n");
    
    return $OpenCA::DBIS::ERROR->{FORK_FAILED};
  }
}

sub stopSigningDaemon {
  my $self = shift;
 
  my $fifo = $_[0] if ($_[0]);
 
  $fifo = $self->{PIDFILE} if (not $fifo); 
 
  ## getting pid from PIDFILE
  if (not open (FD, "<".$fifo)) {
    return $openCA::DBIS::ERROR->{OPEN_PIDFILE_FAILED};
  }

  ## PIDs mit mehr als 10 stellen kenne ich nicht ;-)
  my $s_pid;
  read (FD, $s_pid, 10);

  ## stop daemon
  ## actually no clean daemon shutdown is implemented
  ## if fork on the daemon not failed this should not be 
  ## a problem
  kill 9, int ($s_pid);

  $self->doLog ("killing SigningDaemon with PID ".int ($s_pid)." at ".gmtime ()."\n"); 

  ## try to remove messagequeue
  msgctl (msgget ($self->{MESSAGEKEY}, S_IRUSR | S_IWUSR ), IPC_RMID, undef);

  return 0;
}

sub init {
  my $self = shift;
  my $keys = { @_ };

  $self->{DEBUG} = $keys->{DEBUG} if ($keys->{DEBUG});

  print "  sub init of OpenCA::DBIS\n" if ($self->{DEBUG});

  ## this class can be created for several reasons
  ## 1. signing
  ## 2. backup
  ## 3. backup-verification
  ## 4. database-recovery
  ## 5. database-recovery from backup

  ## actually only signing is supported

  ## general configuration

  print "  general parts ...\n" if ($self->{DEBUG});

  ## used for logverification and signing
  $self->{CERT_FILE}     = $keys->{CERT_FILE}     if ($keys->{CERT_FILE});
  $self->{backend}       = $keys->{SHELL}         if ($keys->{SHELL});

  ## signing will be configured

  print "  configure OpenCA::DBIS for signing\n" if ($self->{DEBUG});

  ## checking for given key (logsigning with/without daemon)
  $self->{KEY_FILE}      = $keys->{KEY_FILE}         if ($keys->{KEY_FILE});
  ## used for key_file and start of signing_daemon
  $self->{PASSWD}        = $keys->{PASSWD}           if ($keys->{PWD});

  ## checking for given pipename
  $self->{PIDFILE}       = $keys->{PIDFILE}       if ($keys->{PIDFILE});
  $self->{LOGFILE}       = $keys->{LOGFILE}       if ($keys->{LOGFILE});
  $self->{MESSAGEKEY}    = $keys->{MESSAGEKEY}    if ($keys->{MESSAGEKEY});
  $self->{MESSAGELENGTH} = $keys->{MESSAGELENGTH} if ($keys->{MESSAGELENGTH});
  $self->{IPC_USER}      = $keys->{IPC_USER}      if ($keys->{IPC_USER});
  $self->{IPC_GROUP}     = $keys->{IPC_GROUP}     if ($keys->{IPC_GROUP});

  ## configure uid
  if ($self->{IPC_USER}) {
    my @passwd = getpwnam ($self->{IPC_USER});
    if (@passwd) {
      $self->{IPC_UID} = $passwd[2];
    }
  } else {
    print "    IPC_UID not given so $<\n" if ($self->{DEBUG});
    $self->{IPC_UID} = $<                 if (not $self->{IPC_UID});
  }

  ## configure group
  if ($self->{IPC_GROUP}) {
    my @passwd = getgrnam ($self->{IPC_GROUP});
    if (@passwd) {
      $self->{IPC_GID} = $passwd[2];
    }
  } else {
    print "    IPC_GID not given so ".getgid."\n" if ($self->{DEBUG});
    $self->{IPC_GID} = getgid                 if (not $self->{IPC_GID}); 
  }

  ## print "    checking for the tools\n" if ($self->{DEBUG});
  ##
  ## return if ( not $self->{tools} = new OpenCA::Tools());

  $self->debug ("  final setting of vars after sub init");

  print "  sub init of OpenCA::DBIS completed\n" if ($self->{DEBUG});

  return 1;
}

sub doLog {
  my $self = shift;

  if (not open (LOGFILE, ">>".$self->{LOGFILE})) {
    print STDOUT "WARNING: cannot write logfile \"".$self->{LOGFILE}."\"\n";
    print STDOUT "MESSAGE: ".$_[0]."\n";
  } else {
    if ($self->{DEBUG}) {
      print STDOUT "LOGMESSAGE: ".$_[0]."\n";
    }
    print LOGFILE "\n".gmtime()." message:\n";
    print LOGFILE $_[0];
    close LOGFILE;
  }
}

sub debug {
  my $self = shift;

  if ($self->{DEBUG}) {

    print ("\n".$_[0]."\n");

    print "    CERT_FILE     ".$self->{CERT_FILE}."\n";
    print "    KEY_FILE      ".$self->{KEY_FILE}."\n";
    print "    PWD           ".$self->{PWD}."\n";
    print "    MESSAGEKEY    ".$self->{MESSAGEKEY}."\n";
    print "    MESSAGELENGTH ".$self->{MESSAGELENGTH}."\n";
    print "    IPC_USER      ".$self->{IPC_USER}."\n";
    print "    IPC_GROUP     ".$self->{IPC_GROUP}."\n";
    print "    IPC_UID       ".$self->{IPC_UID}."\n";
    print "    IPC_GID       ".$self->{IPC_GID}."\n";
    print "    PIDFILE       ".$self->{PIDFILE}."\n";
    print "    LOGFILE       ".$self->{LOGFILE}."\n";
    print "    BACKEND       true\n" if ($self->{backend});
    print "    BACKEND       false\n" if (not $self->{backend});
  }
  return;
}

sub getData {
  my $self = shift;

  if (not open (FIFO, "< $_[0]")) {
    ## hui cannot open fifo
    ## rising alert message
    $self->doLog ("WARNING: OpenCA::DBIS signing daemon cannot open fifo\n".
                  "         this could be an attack or an killed http-request!\n".
                  "         please verify this\n");
    ## exit
    return ("", "");
  }

  my $help;
  my $answer_fifo = "";
  while (read (FIFO, $help, 1) ) {
    last if ($help eq "\n");
    $answer_fifo .= $help;
  }
      
  ## read length of data
  my $h_length = "";
  my $help;
  while (read (FIFO, $help, 1) == 1) {
    last if ($help eq "\n");
    $h_length .= $help;
  }
  my $length = int ($h_length);
    
  ## read data which has to be signed
  my $data;
  if (read (FIFO, $data, $length) < $length) {
    $data = "";
  }

  close FIFO;

  return ($answer_fifo, $data);
}

sub getSignature  {
  ## not for use with object !!!
  ## static function !!!
  shift;
  
  ## first I check for a given cert, key and passwd
  ## second I check for a given pipe
  ## third I check the class itself to be an object
  ##  --> object
  ##    check for configured cert, key and passwd
  ##    check for configured pipe
  ##  --> no object
  ##    check default pipe
  ## return "";
 
  my $keys = { @_ };
  my $mkey = $OpenCA::DBIS::MESSAGEKEY;
  my $mlength = $OpenCA::DBIS::MESSAGELENGTH;

  my $data = $keys->{DATA};

  ## if no data then I return
  if (not $data) {
    return;
  }
  
  ## if I have a cert and a keyfile then I can sign by myself!
  if ($keys->{CERT_FILE} and $keys->{KEY_FILE}) {
    print "  try to get Signature directly\n" if ($keys->{DEBUG});  
    return ($keys->{CERT_FILE}, OpenCA::DBIS->getSigndata (CERT_FILE => $keys->{CERT_FILE},
                                                           KEY_FILE  => $keys->{KEY_FILE},
                                                           PASSWD    => $keys->{PASSWD},
                                                           SHELL     => $keys->{SHELL},
                                                           DATA      => $data));
  }

  ## checking for new keys
  $mkey    = $keys->{MESSAGEKEY}    if ($keys->{MESSAGEKEY});
  $mlength = $keys->{MESSAGELENGTH} if ($keys->{MESSAGELENGTH});
  
  ## last chance 
  return if (not $mkey);
 
  my $tmpfifoOut = "/tmp/".$PID."_out.fifo";
  my $tmpfifoIn  = "/tmp/".$PID."_in.fifo";
  my $msgid;

  print "before msgget\n" if ($keys->{DEBUG});
  return if (not ($msgid = msgget ($mkey, S_IRUSR | S_IWUSR)));
  print "msgid: ".$msgid."\n" if ($keys->{DEBUG});

  ## store fifoname
  my $load .= $tmpfifoIn."\n";
  ## store length
  $load .= sprintf ("%d", length($data))."\n";
  ## store signature
  $load .= $data;
  
  ## mkfifo with 
  ##   O_CREAT|O_TRUNC
  ##   S_IRUSR|S_IWUSR
  ## if (mkfifo ($tmpfifo, O_CREAT|O_TRUNC|S_IRUSR|S_IWUSR) < 0) {
  if (system ('mkfifo', "--mode=600", $tmpfifoIn) < 0) {
    ## mkfifo failed
    return;
  };
  
  ## mkfifo with 
  ##   O_CREAT|O_TRUNC
  ##   S_IRUSR|S_IWUSR
  ## if (mkfifo ($tmpfifo, O_CREAT|O_TRUNC|S_IRUSR|S_IWUSR) < 0) {
  if (system ('mkfifo', "--mode=600", $tmpfifoOut) < 0) {
    ## mkfifo failed
    unlink $tmpfifoIn;
    return;
  };

  if (not msgsnd ($msgid, pack ("L a*", 1, $tmpfifoOut), 0)) {
    unlink $tmpfifoIn;
    unlink $tmpfifoOut;
    return;
  }

  ## open fifo
  if (not open (FIFO, "> ".$tmpfifoOut)) {
    unlink $tmpfifoIn;
    unlink $tmpfifoOut;
    return;
  }
  unlink $tmpfifoOut;
 
  ## write load
  print FIFO $load;

  ## close fifo
  close FIFO;
  
  ## open fifo
  if (not open (FIFO, "<".$tmpfifoIn)) {
    unlink $tmpfifoIn;
    return;
  }
  unlink $tmpfifoIn;
  
  ## read length of data
  my $h_length = "";
  my $help;
  while (read (FIFO, $help, 1) == 1) {
    last if ($help eq "\n");
    $h_length .= $help;
  }
  my $length = int ($h_length);
    
  ## read data which has to be signed
  my $cert;
  if (read (FIFO, $cert, $length) < $length) {
    $cert = "";
  }
      
  ## read length of data
  my $h_length = "";
  my $help;
  while (read (FIFO, $help, 1) == 1) {
    last if ($help eq "\n");
    $h_length .= $help;
  }
  my $length = int ($h_length);
    
  ## read data which has to be signed
  if (read (FIFO, $data, $length) < $length) {
    $data = "";
  }
      
  ## close answer fifo
  close FIFO;
  
  ## return signature
  return ($cert, $data);

}

sub getSigndata {
  shift;
 
  ## I'dont check the values !!!
  ## so be carefull !!!

  ########################################################
  ## ATTENTION OpenSSL->sign only accept files actually
  ########################################################
  my $tmpfile = "/tmp/${$}_data.tmp";                              
  my $keys = { @_ };

  return if (not open( FD, ">$tmpfile" ));
  print FD $keys->{DATA};
  close(FD);                                                                   
  
  return $keys->{SHELL}->sign (DATA_FILE  => $tmpfile,
                                 CERT_FILE  => $keys->{CERT_FILE},
                                 KEY_FILE   => $keys->{KEY_FILE},
                                 PWD        => $keys->{PASSWD});
  
  unlink ($tmpfile);
  
}  


sub getMergedData {
  ## not for use with object !!!
  ## static function !!!
  shift;
  my $keys = { @_ };

  ## I await a hash - don't forget getMergedData(\%hash) not (%hash)
  my @list = [];
  my $data = "";

  ## hash to array
  push @list, keys %{$keys->{DATA}};
  
  ## sort array
  sort > @list;
  
  ## merge fields
  while (scalar (@list)) {
    ## the \n protect us against equal numbers e.g. 13 and 456 vs. 134 and 56
    $data .= $keys->{DATA}->{pop @list}."\n";
  }
  
  ## return data
  return $data;
}

sub getSignatureAnchor {
  ## not for use with object !!!
  ## static function !!!
  shift;

  my $keys = { @_ };
  
  my $logsecurity    = $OpenCA::DBIS::LOGSECURITY;
  my $logperformance = $OpenCA::DBIS::LOGPERFORMANCE;
  my $position       = int ($keys->{position});
  my @list;
  my $i = 0;

  return if (not defined $keys->{position});

  $logsecurity    = $keys->{logsecurity}    if ($keys->{logsecurity});
  $logperformance = $keys->{logperformance} if ($keys->{logperformance});

  while (2**$i <= $position) {
    ## this is very dangerous because on highperformance databases the last and the last -1 
    ## transaction are both active so because of transactionisolation I don't
    ## see the last-1 logrecord and so the signature is false !!!
    ## alternative1: lock the hole table -> very bad idea
    ## alternative2: don't accept logsecurity == 0 any longer
    ## alternative3: don't touch the logsecurity but introduce a logperformance
    ##               logperformance >= 8 which cause at minimum a distance
    ##               of 2**8 = 256 logrecords
    ## take alternative3
    $list [scalar (@list)] = $position - 2**$i;
    $i++;
  }
  for ($i=0; ($i < $logperformance) and (scalar (@list)); $i++) {
    shift (@list);
  }
  if ($logsecurity) {
    while (scalar (@list) > $logsecurity) {
      shift (@list);
    }
  }
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!
  
=head1 NAME
  
OpenCA::DBIS - Perl Certificates DBI Extention.
 
=head1 SYNOPSIS
  
use OpenCA::DBIS;
 
=head1 DESCRIPTION

Attention this is not a documentation. Only dummy from OpenCA::DBI alpha!!!
  
Attention if you are using any database related private functions
at yourself then you have to use the following method:
 
Block: {
doConnect
doQuery until the first returncode is -1
        then doRollback
             doDisconnect
if never do Qery fails then
doCommit
if returnvalue is -1
then doRollback
     doDisconnect
else doDisconnect
}                                                                                             
you can repeat this block so often as you want until the first time
doConnect returns -1. So long this not happens you can try to get a
successful transaction.
 
Sorry, no documentation available at the moment. Please take a look
at the prova.pl program you find in main directory of the package.
 
Here there is a list of the current available functions. Where there
is (*) mark, the function is to be considered private and not public.
 
        new {};
                build a new DBI object;
 
        getIndex {};
                empty; only for compatibility with OpenCA::DB
 
        saveIndex {};
                empty; only for compatibility with OpenCA::DB
 
        initDB {};
                initialize the DB structure;
 
        operateDB {*};
                handle the direct DB and SQL-stuff for initDB
 
        getReferences {};
                empty; only for compatibility with OpenCA::DB
 
        getBaseType {};
                get Base datatye given a generic one ( i.e. from PENDING_                                    REQUEST to REQUEST);
 
        getSearchAttributes (*) {};
                get a list of attributes for the search facility;
 
        storeItem {};
                store a given object (OpenCA::XXXX);
                this is where I'm actually working on;
 
        getItem {};
                retrieve an object given the serial number;
 
        getNextItem {};
                get next object (or serial) given a serial;
 
        getPrevItem {};
 
        deleteItem {};
 
        elements {};
                returns number of elements of a given DATATYPE;
 
        rows {};
                return number of elements matching a search;
 
        searchItem {};
                returns objects/serials matching the search on generic
                datatypes (i.e. CERTIFICATE, REQUEST);
 
        searchItemDB (*) {};
                returns objects/serials matching the search on exact
                datatypes (i.e. VALID_CERTIFICATE, PENDING_REQUEST);                          
        getTimeString {};
                not currently used;
 
=head1 AUTHOR
 
Michael Bell <michael.bell@web.de>
 
=head1 SEE ALSO
 
OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::REQ,
OpenCA::TRIStateCGI, OpenCA::Configuration, OpenCA::Tools
 
=cut                                                                                         
