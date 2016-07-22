##use strict;
use warnings;
use Text::xSV;
use Text::CSV_XS;
use DBI;
use SQL::Abstract;


######converting a file into CSV

#open a file1 to read
my $filename1 = "log.txt";

open(my $f1, '<',"$filename1");

#open a file2 to write
my $filename2 = "log1.txt";

open(my $f2, '>',"$filename2");

#####read all lines remove spaces in between
###write to new file
while (<$f1>) {
    
    s/\t/ /g;
    s/\s+\Z/\n/;
    s/ +/,/g;
    s/,length=/,/g;
    s/,xy=/,/g;
    s/,region=/,/g;
    s/,run=/,/g;
    print $f2 $_;
    }
close $f1;
close $f2;




######################
     

open(my $fh, $filename2);
my $CVEfilename = 'CVE.txt';
open(my $fhc, '>', $CVEfilename) ;
my $Accessfilename = 'Acess.txt';
open(my $fha, '>', $Accessfilename) ;
     
 while (my $row = <$fh>) {
   chomp $row;
  
      if($row =~/((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))/){

print $fha "$row\n";

} else {
print $fhc "$row\n";
}
    }

close $fh;
close $fha;
close $fhc;

###################
my $driver   = "SQLite"; 
my $database = "test.db";
my $dsn = "DBI:$driver:dbname=$database";
my $userid = "";
my $password = "";
##creating a test data base
my $dbh = DBI->connect($dsn, $userid, $password, { RaiseError => 1 }) 
                      or die $DBI::errstr;

print "Opened database successfully\n";

##create a  CVE data Table
##Date(2016-05-27), Time(22:08:44.403585), Severity(medium), #Event ID(8860), Hostname(host534.example.com), Protocol(SCTP), #CVE ID(CVE-2016-6179)
    my $stmt11 = qq(DROP TABLE CVETABLE );
	$dbh->do($stmt11);
my $stmt = qq(CREATE TABLE CVETABLE (
      Date     REAL,
      Time     REAL,
      Severity VARCHAR,
      EventID  INTEGER,
      Hostname VARCHAR,
      Protocol VARCHAR,
      CVEID VARCHAR	  
        ););
my $rv = $dbh->do($stmt);
if($rv < 0){
   print $DBI::errstr;
} else {
   print "CVETABLE created successfully\n";
}
#my $stmt11 = qq(DROP TABLE CVETABLE );

    
##Date(2016-05-27), Time(22:08:44.403585), Severity(medium), #Event ID(8860), Source Address(1.1.1.1), Destination Address(2.2.2.2),user(tom)
my $stmt12 = qq(DROP TABLE ACCESSTABLE );
$dbh->do($stmt12);
    
my $stmt1 = qq(CREATE TABLE ACCESSTABLE (
      Date     REAL,
      Time     REAL,
      Severity VARCHAR,
      EventID  INTEGER,
      SourceAddress REAL,
      DestinationAddress REAL,
      user    VARCHAR
      ););
my $rv1 = $dbh->do($stmt1);
if($rv1 < 0){
   print $DBI::errstr;
} else {
   print "ACCESSTABLE created successfully\n";
}


my  $Sql = 'INSERT INTO CVETABLE VALUES (?,?,?,?,?,?,?)';
my $sth = $dbh->prepare($Sql);
my $csv = Text::CSV_XS->new or die;
open my $fh, "<", "CVE.txt";
while(my $row = $csv->getline($fh)) {
    
	
	if((@$row == 6 )&($$row[2] =~ /\d+/)){
	
	 splice @$row,2,0,'NOEVENT';
	}
	
    $sth->execute(@$row);
}
$csv->eof;
close $fh;

$sth->finish;  
my  $Sql1 = 'INSERT INTO ACCESSTABLE VALUES (?,?,?,?,?,?,?)';
my $sth1 = $dbh->prepare($Sql1);
my $csv = Text::CSV_XS->new or die;
open my $fh11, "<", "Acess.txt";
while(my $row = $csv->getline($fh11)) {
   
	
	 if((@$row == 6 )){
		 splice @$row,6,0,'NULL';
	}
		
    $sth->execute(@$row);
}
$csv->eof;
close $fh11;

$sth1->finish;  


#my $getkey = $dbh->prepare("SELECT Severity FROM CVETABLE");
my $getkey = $dbh->prepare("select  Severity from CVETABLE where Severity ='critical'");
$getkey->execute;
@row = $getkey->fetchrow_array();

print "############\n";
print "no.of entries are $#row\n";
print "############\n";
$count = 0;
while (@row = $getkey->fetchrow_array()) {
        
        print " count is $count #T##@row\n";
        $count++;
        }
print "kishore\n";
print "Operation done successfully\n";
print "kishore\n";


  
