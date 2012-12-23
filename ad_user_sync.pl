#!/usr/bin/perl
=pod
MAYBE SOME ACCOUNTS DON"T GET CREATED FULLY DUE TO SID CONFLICTS WITH DELETED PENT ACCTS OR MAYBE NEED TO GENERATESTUDENTATTRS FOR NEW ACCTS
 Things to do
 email reports to schools 
 make sure profile is created in correct place and chown'ed and chmod'ed
  fix checkProfile and confirm proper functioning and creation of symlinks on existing profiles
  re-endable password verify
  finish DBLOG output
  put log counts at the top of the log and email
  make sure student year is a real path
  eventually, student folders should be created in their student year path, right? (how does this affect LTSP?)
  test adenable for jawirf19 - should all be set to 66082?
  do counts on file system changes
  write code for populating uid/password from adUsers if studentId matches
  make sure nightly chown is running
  integrate counts into loggers hash
  check for chown on checkProfile
=cut

###################################################
=pod
build a CSV file which admod.exe can use to sync changes to active directory

Process:
1) Dump AD user records and parse
2) Query DB user records
3) For each user in DB, match to AD by studentID
4) If student is not in AD:
  A) if student has a user record with sid value in DB and AD has a user record with that sid, assume a match and goto 5)
  B) generate new attributes (uid, password, uidNumber, etc)
  C) generate csv records to add to AD
  D) create user home
  E) log creation date/time and other info in DB
5) If student is in AD do the following, logging any actions taken in the DB
  A) compare DB to AD attributes - if changes are required
    I) generate csv records to edit AD
    II) log changes and date/time in DB
    III) if rename, call rename script (to be written) which does:
      a) rename user record in AD
      b) remap uidNumber to new uid in all linux servers if necessary
      c) rename home folder on linux and chown
      d) rename in Gmail
    IV) if status changed in DB, change status in AD to match
    V) if user-specific (non-pentamation) attributes are not defined in DB, update these in DB from AD
    VI) if required profile folders or symlinks are missing, report add back in iand report in output log - backups must be restored manually
  B) if authTest has not happened since defined amount of time, attempt authTest - if failed, reset password in AD
  C) Check and repair student profile if necessary (repairs symlinks by first moving files to where they should be, such as My Documents->Documents)

Notes:
  Any records not present in the DB hash are disabled in AD (never deleted)
  If status=A, doNotDisable=1 or nocap=1 in the DB then the record is selected and the student will be active in AD
  If doNotRename=1 in the DB then the student's uid and email will not be changed in case of a name change in Pentamation, but their displayName, sn and given name will change in AD and Gmail

=cut
##################################################

### usage: adsync.pl [1] [1] ###
my $test=$ARGV[0]; #test = 1 means build csv, but don't send to doadm1
my $nodump=$ARGV[1]; #nodump = 1 means use the existing addump.csv to build changes - don't pull a new file from doadm1

use Data::Dumper;
use Net::SSH;
use Digest::SHA1  qw(sha1 sha1_hex sha1_base64);

$config_file='ad_user_sync_config.pm';
unless (-e $config_file) {`cp $config_file.template $config_file`;}

require $config_file;

###
### Define how various changes are logged
###   count: what counter to increment on change
###   email: what message to report in email log (also goes to log file)
###   changeLogAttr: attribute to list with old and new values in studentChangesLog (also goes to log file and email) (1=use args->{attr} passed by caller)
###   changeLogField: field and value to set in studentChangesLog
###   detail: more info to be printed in log file
###
my %loggers=(
  create=>{
    count=>'created',
    email=>'created user',
    changeLogAttr=>undef,
    changeLogField=>['created',1]
  },
  enable=>{
    count=>'enabled',
    email=>'enabled user',
    changeLogAttr=>undef,
    changeLogField=>['setAccountStatus',1]
  },
  disable=>{
    count=>'disabled',
    email=>'disabled user',
    changeLogAttr=>undef,
    changeLogField=>['setAccountStatus',-1]
  },
  cannotBeDisabled=>{
    failCount=>'cannotBeDisabled',
  },
  postponedDiabling=>{
    failCount=>'postponedDiabling',
  },
  nameChange=>{
    count=>'renamed',
    changeLogAttr=>'name'
  },
  passwordReset=>{
    count=>'resetPasswords',
    changeLogAttr=>'password'
  },
  modify=>{
    changeLogAttr=>1
  },
  addToGroup=>{
    count=>'addedToGroups'
  },
  deleteFromGroup=>{
    count=>'deletedFromGroups'
  },
  cannotAddToGroup=>{
    failCount=>'cannotAddToGroup'
  },
  cannotDeleteFromGroup=>{
    failCount=>'cannotDeleteFromGroup'
  },
  profileSubfolderMissing=>{
    warningCount=>'profileSubfolderMissing',
    warning=>'Manual restore of files might be required',
    warnings=>''
  }
);

if ($test) {
  logger({detail=>"____________________\nINITIAITE TEST SYNC\n   No changes will be made to the database or AD\n____________________\n"});
}

$path="/data/sis/adsync";
###
### Open log and script files ###
### Each script file is run by a different AdMod.exe command on doadm1, so each type of change is put in a different file
open (L,'>/var/log/adsync.log');    #the log file
open (ADENA,">$path/adenable.csv"); #enable accounts in AD
open (ADDIS,">$path/addisable.csv");#disable accounts in AD
open (ADMOD,">$path/admod.csv");    #modify accounts in AD
open (ADADD,">$path/adadd.csv");    #add accounts to AD
open (ADREN,">$path/adrename.sh");  #rename accounts in AD
open (ADGRP,">$path/adgroups.sh");  #change group memberships in AD
open (ADPWD,">$path/adpwd.sh");     #set password in AD
open (FSMOD,">$path/fsmod.sh");     #shell script to create and chown user profiles
open (DBMOD,">$path/dbmod.sql");    #modify the local database
open (DBLOG,">$path/dblog.sql");    #write log entries to local database

### print file headers ###
my %outputFields=(adadd=>["dn","objectClass","initials","cn","description","displayName",$dbUsersPK,"gidNumber","givenName","loginShell","mail","name","sAMAccountName","sn","uidNumber","uid","userPrincipalName","unixHomeDirectory"],admod=>["dn","initials","description","displayName",$dbUsersPK,"gidNumber","givenName","loginShell","mail","sAMAccountName","sn","uidNumber","uid","userPrincipalName","unixHomeDirectory","unixUserPassword"]);
print ADMOD '"'.join('","',@{$outputFields{admod}})."\"\n";
print ADADD '"'.join('","',@{$outputFields{adadd}})."\"\n";
print ADENA "\"dn\",\"userAccountControl\"\n";
print ADDIS "\"dn\",\"userAccountControl\"\n";
print ADREN "#!/bin/sh\n";
print ADGRP "#!/bin/sh\n";
print ADPWD "#!/bin/sh\nPATH=/usr/local/bin:/bin:/opt/gcc.3.3/bin:/usr/contrib/bin:/usr/X11R6/bin:/usr/local/bin:/usr/contrib/win32/bin:/dev/fs/C/Windows/System32:/dev/fs/C/Windows/SUA/common\n";
print FSMOD "#!/bin/sh\n";


### $rpt is the report message body ###
my $rpt='';

### Current school year (09-10 = 10) ###
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =localtime(time);
$currYear=$year+1900;
if ($mon>6) {$currYear++;}

### Folders that should be present in all user profile folders ###
### first-level proflie folder names
my @profileFolders=('Desktop','Documents','Downloads','Movies','Music','Pictures');
### {'link_path_relative_to_user_profile_root'=>'target_path_relative_to_link_path'}
### the resulting command for {'Documents/My Music'=>'../Music'} when profile path='/Users/abcdef11' is: ln -s ../Music /Users/abcdef11/Documents/My\ Music
### this way the links are good no matter where the profile folder might be moved to
my @profileSymlinks=({'My Documents'=>'./Documents'},{'My Pictures'=>'./Pictures'},{'Documents/My Music'=>'../Music'},{'Documents/My Videos'=>'../Movies'},{'Documents/Downloads'=>'../Downloads'});

### memberships changes for relevant AD groups, built as mergeGroups sub is called
my %groupMemChanges=();


### Parse ad dump ###
my $adUsers=adUsers();

###
### Define the attribute map between the database and AD ###
###
%attrMap=(
  ### these are from the database ###
  $dbUsersPK=>$adUsersPK,
  'firstName'=>'givenName',
  'lastName'=>'sn',
  'uidNumber'=>'uidNumber',
  'uid'=>'uid',
  'description'=>'description',
  'sid'=>'objectSid',
  ### these are generated in this script ###
  'cn'=>'cn',
  'displayName'=>'displayName',
  'loginShell'=>'loginShell',
  'gidNumber'=>'gidNumber',
  'mail'=>'mail',
  'name'=>'name',
  'primaryGroupID'=>'primaryGroupID',
  'sAMAccountName'=>'sAMAccountName',
  'userPrincipalName'=>'userPrincipalName',
  'memberOf'=>'memberOf',
  'unixHomeDirectory'=>'unixHomeDirectory',
  'unixUserPassword'=>'unixUserPassword',
  'dn'=>'dn',
  'objectClass'=>'objectClass',
  'initials'=>'initials'
);

###
### Build a reverse attribute map keyed on AD attributes
###
my %rAttrMap=();
foreach my $attr (keys %attrMap) {
  $rAttrMap{$attrMap{$attr}}=$attr;
}


###
### Connect to database ###
###
my $dbh;
DBInit({db=>$dbName,user=>$dbAdminUser,pwd=>$dbAdminPass});

###
### Get users info from the database ###
###
$dbUsers=doQuery({query=>$dbUsersQuery,key=>$dbUsersPK});

###
### Get users count from both sources
###
$adCount=0;
$dbCount=0;
foreach $s (keys %$adUsers) {$adCount++;}
logger({email=>"$adCount ".$syncUserType."s in ldap"});
foreach $s (keys %$dbUsers) {$dbCount++;}
logger({email=>"$dbCount active "$syncUserType."s in the database"});

###
### Abort sync if too few users were found, assuming one or more sources is unavailable
###
unless ($adCount>100 && $dbCount>100) {
  logger({email=>"Looks like the directory server didn't reply to the search properly or db didn't return ".$syncUserType."s.\nKilling sync\n"}); 
  sendEmail($logRecipient,$logSender,"$syncUserType Sync Report",$rpt);
  exit 0;
}

###
### Get unique attributes from AD 
### This returns a hash like
### $u->{uids}{uid}=1...
### $u->{uidNumbers}{uidNumber}=1...
### @{$u->{freeUidNumbers}}=(#,#,#)
###
my $uniqueAttrs=getUniqueAttrs();

###
### For each user:
### make new AD user if not in AD
### or sync with existing AD account
### 
foreach my $sid (keys %$dbUsers) {
  ### if uid is not set in db, assume this is a new user and generate uid and uidNumber
  unless ($dbUsers->{$sid}{uid}) {
    $dbUsers->{$sid}{isNew}=1;
    $dbUsers->{$sid}{uid}=uniqueUid($sid);
    $dbUsers->{$sid}{uidNumber}=uniqueUidNumber();
  }
  my $uid=$dbUsers->{$sid}{uid};
  ### generate attributes not stored in database ###
  generateUserAttributes($sid);
  ### set default groups ###
	$dbUsers->{$sid}{defaultGroups}=defaultGroups($sid);
  if (defined $locationAttrs{$dbUsers->{$sid}{$locationAttrDBKey}}) {
		$dbUsers->{$sid}{defaultGroups}{"CN=$locationAttrs{$dbUsers->{$sid}{$locationAttrDBKey}}{group},$locationAttrs{$dbUsers->{$sid}{$locationAttrDBKey}}{groupOU}"}=$locationAttrs{$dbUsers->{$sid}{$locationAttrDBKey}}{group};
  }
  else {
    logger({sid=>$sid,email=>"$uid school: '$dbUsers->{$sid}{school}' has no defined attributes"});
  }

  ### If user already exists in AD, check for changes to AD
#  print L "check if student $sid $uid is in ldap...\n";
  if (defined $adUsers->{$uid}) {
    ## merge default groups with AD groups for this user ##
    $dbUsers->{$sid}{memberOf}=mergeGroups($sid,$adUsers->{$uid}{groups});
    my $admod=0; #flag for whether this student needs to be changed in AD
    ## set SID from previous new user creation if it wasn't in the DB - this is stored in case uid is changed by accident in DB ##
    if ($dbUsers->{$sid}{sid} ne $adUsers->{$uid}{objectSid}) {
      $dbUsers->{$sid}{sid}=$adUsers->{$uid}{objectSid};
      print DBMOD sidUpdateQuery($sid);
    }
    ## check for disabled ##
    if ($adUsers->{$uid}{disabled}) {
      logger({sid=>$sid,log=>'enable'});
      enableStudent($sid);
      print ADENA "\"$adUsers->{$uid}{dn}\",\"$adUsers->{$uid}{userAccountControl}\"\n";
    }
    ## check for name change ##
    if (((uc($dbUsers->{$sid}{firstName}) ne uc($adUsers->{$uid}{givenName})) || (uc($dbUsers->{$sid}{lastName}) ne uc($adUsers->{$uid}{sn}))) and not($dbUsers->{$sid}{doNotRename})) {
      my $newName=$dbUsers->{$sid}{displayName};
      logger({sid=>$sid,log=>'nameChange',old=>$dbUsers->{$sid}{name},new=>$newName});
      print DBMOD "update users set name='$newName' where studentId=$sid;\n"; 
      $admod=1; # flag for changes
    }
### authtest.pl now handles all password verification ###
    ## check for password change ##
#    if (!validAuth($sid,$uid,$dbUsers->{$sid}{password})) {
#      my $email=undef;
#      logger({sid=>$sid,log=>'passwordReset',old=>$dbUsers->{$sid}{password},new=>$dbUsers->{$sid}{password},email=>$email});
#      $admod=1;
#      print ADPWD "net user $uid $dbUsers->{$sid}{password} /domain\n";
#    }
#########################################################
    ## check for other changes ##
    my @otherAttrs=($dbUsersPK,'uidNumber','uid','loginShell','mail','unixHomeDirectory','description');
    foreach my $adAttr (@otherAttrs) {
      my $dbAttr=$rAttrMap{$adAttr};
      if ($dbUsers->{$sid}{$dbAttr} ne $adUsers->{$uid}{$adAttr}) {
        logger({sid=>$sid,log=>'modify',attr=>$adAttr,old=>$adUsers->{$uid}{$adAttr},new=>$dbUsers->{$sid}{$dbAttr}});
        $admod=1;
      }
    }
    ## make sure student has a proper record in the uids table ##
    unless ($dbUsers->{$sid}{uUid} eq $dbUsers->{$sid}{uid} && $dbUsers->{$sid}{uUserId}== $dbUsers->{$sid}{userId} && $dbUsers->{$sid}{uPrime}==1) {
      logger({detail=>"uids record not present or incorrect for $dbUsers->{$sid}{uid} - fixing"});
      print DBMOD "select \@userId:=null; select \@userId:=userId from users where uid='$dbUsers->{$sid}{uid}';\n";
      print DBMOD "insert into uids set uid='$dbUsers->{$sid}{uid}',userId=\@userId,prime=1;\n";
      print DBMOD "update uids set prime=1,userId=\@userId where uid='$dbUsers->{$sid}{uid}';\n";
    }
    ## implement changes if necessary ##
    if ($admod) {
      logger({detail=>"Implement ADMOD for $dbUsers->{$sid}{uid}"});
      my @vals=();
      foreach my $field (@{$outputFields{admod}}) {
        push(@vals,"\"$dbUsers->{$sid}{$rAttrMap{$field}}\"");
      }
      print ADMOD join(',',@vals)."\n";
    }
  }
  else {
    logger({detail=>"Create new acct for $sid $dbUsers->{$sid}{firstName} $dbUsers->{$sid}{lastName}\n"});
  	### create new acct ###
    unless ($dbUsers->{$sid}{password}>0) {$dbUsers->{$sid}{password}=genpwd();}
    $dbUsers->{$sid}{unixUserPassword}=sha1_hex($dbUsers->{$sid}{password});
    ## The description used to hold the password. That was insecure so we don't do that anymore, but keep it populated as a decoy. It's funny. ###
    $dbUsers->{$sid}{description}=genpwd();
    ## update or create database entry ##
    my $dbset="name='$dbUsers->{$sid}{lastName}, $dbUsers->{$sid}{firstName}',studentId=$sid,password='$dbUsers->{$sid}{password}',uid='$dbUsers->{$sid}{uid}',dn='$dbUsers->{$sid}{dn}',uidNumber=$dbUsers->{$sid}{uidNumber},adUidNumber=$dbUsers->{$sid}{uidNumber}, adPassword='$dbUsers->{$sid}{password}',addn='$dbUsers->{$sid}{dn}'";
    if ($dbUsers->{$sid}{inDB}) {
      print DBMOD "update users set $dbset where studentId=$sid;\n";
    }
    else {
      print DBMOD <<EOF;
insert into users set $dbset, description='$dbUsers->{$sid}{description}', created=now();
select \@userId:=null;
select \@userId:=userId from users where studentId=$sid;
insert into uids set userid=\@userId,uid='$dbUsers->{$sid}{uid}',prime=1;
EOF
    }
    ## add to AD ##
    my @vals=();
    foreach my $field (@{$outputFields{adadd}}) {
      push(@vals,"\"$dbUsers->{$sid}{$rAttrMap{$field}}\"");
    }
    print ADADD join(',',@vals)."\n";
    logger({sid=>$sid,log=>'create'});
    ## merge default groups with an empty hash for this user ##
    $dbUsers->{$sid}{memberOf}=mergeGroups($sid,{});
    ## enable user ##
    print ADENA "\"$dbUsers->{$sid}{dn}\",\"66080\"\n";
    ## set password ##
    print ADPWD "net user $uid $dbUsers->{$sid}{password} /domain\n";
	}
  ### Always make sure profile is present and correct (also creates profile for new students)
  checkProfile($sid);
  if ($dbUsers->{$sid}{logged}) {
    print DBLOG "insert into studentChangesLog set studentId=$sid";
    foreach my $field (keys %{$dbUsers->{$sid}{changes}}) {
      my $val=$dbUsers->{$sid}{changes}{$field};
      if ($field eq 'description') {
        $val=~s/\'/\\'/g;
        $val=~s/\n/\\n/g;
        $val="'$val'";
      }
      print DBLOG ", $field=$val";
    }
    print DBLOG ";\n";
    logger({email=>"----------"});
  }
  if ($dbUsers->{$sid}{modified}) {
    $counts{modified}++;
  }
}

### look for accounts to disabled ###
### This will only disable 100 at a time for safety ###
my $c=0;
foreach my $uid (keys %$adUsers) {
  unless (($adUsers->{$uid}{$adUsersPK}>0 && defined $dbUsers->{$adUsers->{$uid}{$adUsersPK}}) || $adUsers->{$uid}{disabled}) {
    if ($uid =~ /^\w{6}\d{2}$/ || 1==1) {
      if ($c<100) {
        logger({sid=>0,log=>'disable',email=>"Disable user $uid $dbUsersPK=$adUsers->{$uid}{$adUsersPK} adDisabled=$adUsers->{$uid}{disabled}"});
        disableStudent($uid);
        $counts{modified}++;
        print ADDIS "\"$adUsers->{$uid}{dn}\",\"$adUsers->{$uid}{userAccountControl}\"\n";
      }
      else {
        logger({sid=>0,log=>'postponedDisabling'});
      }
      $c++;
    }
    else {
      logger({sid=>0,log=>'cannotBeDisabled',email=>"User $uid not disabled due to nonstandard student uid - REQUIRES MANUAL DISABLING"});
    }
  }
}
if ($c>0) {
  if ($c<101) {
    logger({email=>"$c student accounts disabled"});
  }
  else {
    logger({email=>"100 student accounts disabled\n".($c-100)." student accounts pending disable next sync"});
  }
}

### print changes to groups ###
my %ops=('delete'=>'--','add'=>'++');
foreach my $dn (keys %groupMemChanges) {
  foreach my $op (keys %ops) {
    my $sop=$ops{$op};
    my $line="$admod_path -b $dn \"member:$sop:";
    my $mems='';
    foreach my $memdn (keys %{$groupMemChanges{$dn}{$op}}) {
      $mems.="$memdn;";
    }
    if ($mems) {
      $line.=substr($mems,0,-1)."\"\n";
#      print L "group line for $dn=\n$line\n";
      print ADGRP $line;
    }
  }
}

close (ADDIS);
close (ADENA);
close (ADMOD);
close (ADADD);
close (ADREN);
close (ADGRP);
close (ADPWD);
close (DBMOD);
close (DBLOG);

if ($test) {
  logger({email=>"____________________\nTEST COMPLETE\n____________________"});
}
else {
  logger({email=>"Update Results\n"});
  ### copy files to AD server and process ###
  `scp $path/addisable.csv administrator\@$adm:/`;
  `scp $path/adenable.csv administrator\@$adm:/`;
  `scp $path/adadd.csv administrator\@$adm:/`;
  `scp $path/adgroups.sh administrator\@$adm:/`;
  `scp $path/admod.csv administrator\@$adm:/`;
  `scp $path/adrename.sh administrator\@$adm:/`;
  `scp $path/adpwd.sh administrator\@$adm:/`;
  logger({email=>"____________________\nRUN AD UPDATES\n"});
  $result=`ssh administrator\@$adm "/bin/sh /adupdate.sh"`;
  logger({email=>$result});
  logger({email=>"____________________\nRUN DATABASE UPDATES\n"});
  $result=`/usr/bin/mysql -u plws8a3ksksaA9A -f sis < $path/dbmod.sql`;
  logger({email=>$result});
  $result=`/usr/bin/mysql -u plws8a3ksksaA9A -f sis < $path/dblog.sql`;
  logger({email=>"____________________\nRUN FILE SYSTEM UPDATES\n"});
  $result=`/bin/sh $path/fsmod.sh 2>&1`;
  logger({email=>$result});
  logger({email=>"____________________\nSTUDENT SYNC COMPLETE\n"});
}

### put counts at top of email && bottom of log ###
my $counts="Student Sync Report:\n\n";
my $modified=$counts{modified};
delete $counts{modified};
foreach my $key (keys %counts) {
  $counts.=$counts{$key}." students $key\n";
}
$counts.="----------------------------\n$modified Total Students Modified\n\n";
### and failCounts
foreach my $key (keys %failCounts) {
  $counts.=$failCounts{$key}." $key\n";
}
### and warningCounts
foreach my $key (keys %warningCounts) {
  $counts.="$warningCounts->{$key} $loggers->{$key}{warning}\n$loggers->{$key}{warnings}\n";
}
$counts.="\n";
print L $counts;
close(L);
### email report ###
sendEmail($logRecipient,$logSender,'Student Sync Report',"$counts\n$rpt");


#################################
#         subroutines           #
#################################

###
### send an email
###
sub sendEmail {
  my ($to, $from, $subject, $message) = @_;
  my $d=`date`;
  print "send mail from $from to $to subj $subject\n";
  my $sendmail = '/usr/lib/sendmail';
  open(MAIL, "|$sendmail -oi -t");
    print MAIL "From: $from\n";
    print MAIL "To: $to\n";
    print MAIL "Subject: $subject - $d\n\n";
    print MAIL "$message\n";
  close(MAIL);
} 

###
### generate attributes which are based on other attributes dbStudent
###
sub generateUserAttributes {
  my ($sid)=@_;
  if ($dbUsers->{$sid}{uid}) {
    my $uid=$dbUsers->{$sid}{uid};
    $dbUsers->{$sid}{studentYear}=substr($uid,-2); #studentYear is usually gradYear, but gradYear can change from Pentamation whereas uid, which is based on it, should not
    if ($dbUsers->{$sid}{studentYear} eq 'xx') {
      ## exception for paranoid parents who don't want whoever might decipher our user name convention to know what year their student is supposed to graduate
      $dbUsers->{$sid}{studentYear}=substr($dbUsers->{$sid}{gradYear},-2);
    }
    ### generate attributes not stored in database ###
    $relativeProfilePath="$dbUsers->{$sid}{studentYear}/$uid";
    $dbUsers->{$sid}{cn}=$uid;
    $dbUsers->{$sid}{dn}="CN=$uid,$syncUserBase";
    $dbUsers->{$sid}{initials}=uc(substr($dbUsers->{$sid}{firstName},0,1)).uc(substr($dbUsers->{$sid}{lastName},0,1));
    $dbUsers->{$sid}{loginShell}=$loginShell;
    $dbUsers->{$sid}{gidNumber}=$gidNumber;
    $dbUsers->{$sid}{mail}="$uid\@$mailDomain";
    $dbUsers->{$sid}{name}=$uid;
    $dbUsers->{$sid}{primaryGroupID}=513;
    $dbUsers->{$sid}{sAMAccountName}=$uid;
    $dbUsers->{$sid}{userPrincipalName}="$uid\@$domain";
    $dbUsers->{$sid}{unixHomeDirectory}="/$relativeProfilesPath/$relativeProfilePath";
    $dbUsers->{$sid}{unixUserPassword}=sha1_hex($dbUsers->{$sid}{password});
    $dbUsers->{$sid}{objectClass}='top;person;organizationalPerson;user';
    $dbUsers->{$sid}{displayName}="$dbUsers->{$sid}{firstName} $dbUsers->{$sid}{lastName}";
    $dbUsers->{$sid}{profileFolderPath}="/$profileServerNFSPath/$relativeProfilesPath/$relativeProfilePath";
  }
  else {
    logger({detail=>"Cannot generate attributes without a uid for student: $sid"});
  }
}


sub mergeGroups {
  ### delete exclusive groups not in student's defaultGroups from adGroups and merge defaultGroups into adGroups
  ### returns the memberOf string, which is a concatenation of the final groups
  ### this edits adGroups in adUsers hash
  my ($sid,$adStudentGroups)=@_;
#  print L "merge groups for $memdn\ndefaultGroups=";
#  print L Dumper $defaultGroups;
#  print L "adGroups=";
#  print L Dumper $adGroups;
  ### $defaultGroups is an array of group DNs
  ### $adGroups is a hash of group DNs with values of CNs
  ### first, delete exclusive groups from adGroups
  my $memdn=$dbUsers->{$sid}{dn};
  my $uid=$dbUsers->{$sid}{uid};
  my $defaultGroups=$dbUsers->{$sid}{defaultGroups};
  foreach $dn (keys %$adStudentGroups) {
    if (defined $exclusiveGroups{$dn} && !defined $defaultGroups->{$dn}) {
      delete $adStudentGroups->{$dn};
      $dn=~/CN=(\S+?),/;
      my $cn=$1;
      ### flag this change in AD if $maxGroupChanges has not been reached for removing from this $cn
      if ($groupMemChanges{$dn}{deleteCount}<$maxGroupChanges) {
        $groupMemChanges{$dn}{deleteCount}++;
        $groupMemChanges{$dn}{delete}{$memdn}=1;
        logger({sid=>$sid,log=>'deleteFromGroup',email=>"Delete $uid from $cn"});
      }
      else {
        logger({email=>"Failed to delete $uid from $cn - admod limit exceeded\n"});
      }
    }
  }
  ### next, add in defaultGroups
  foreach $dn (keys %$defaultGroups) {
    if (!defined $adStudentGroups->{$dn} && $dn !~ /xx/) { #student uid that ends in xx is a special case paranoid parents who don't want graduation year in uid
      $adStudentGroups->{$dn}=$defaultGroups->{$dn};
      ### flag this change in AD if $maxGroupChanges has not ben reached for adding to this $cn
      if ($groupMemChanges{$dn}{addCount}<$maxGroupChanges) {
        $groupMemChanges{$dn}{add}{$memdn}=1;
        $groupMemChanges{$dn}{addCount}++;
        logger({sid=>$sid,log=>'addToGroup',email=>"Add $uid to $defaultGroups->{$dn}"});
      }
      else {
        logger({email=>"Failed to add $uid to $defaultGroups->{$dn} - admod limit exceeded\n"});
      }
    }
  }
  ### last, build the memberOf string
  $memberOf='';
  foreach $dn (keys %$adStudentGroups) {
    $memberOf.="$dn;";
  }
  $memberOf=substr($memberOf,0,-1);
  return $memberOf;
}

###
### set an exception flag on a user account (presently not used)
### usage: setException({uidNumber=>uidNumber,exception=>'name',status=>[0|1]});
### status: 1=exception set, 0=exception unset
# userExceptionFlagIndex | name              | description                                                      |
#+------------------------+-------------------+------------------------------------------------------------------+
#|                      1 | AuthFailed        | OD Account Authentication Failed                                 | 
#|                      2 | ProfileFailed     | Home folder verification failed                                  | 
#|                      4 | NoEmplID          | OD employeeID attribute not present                              | 
#|                      8 | UserOnWrongServer | User group does not match home server                            | 
#|                     16 | UserAtWrongSchool | Grade does not match school                                      | 
#|                     32 | UIDGradeMismatch  | uid does not match grade                                         | 
#|                     64 | UIDMismatch       | uid needs to be changed or two students have one studentId in OD | 

sub setException {
	my ($args)=@_;
print "set exception ".Dumper $args;
	if (defined $exceptionList->{$args->{name}} && $args->{uidNumber}) {
		$exp=$exceptionList->{$args->{name}}{userExceptionFlagIndex};
		if ($args->{status}) {
			### set the exception flag
			doQuery({query=>"update users set exceptions=exceptions | $exp where uidNumber=$args->{uidNumber}"});
		} 
		else {
			### clear the exception flag
			doQuery({query=>"update users set exceptions=exceptions ^ $exp where uidNumber=$args->{uidNumber}"});
		}
	}
	else {return 0;}
	return 1;
}


###
### Test user authentication on a given server
### returns 1 on success or 0 on failure
###

my $pwdTests=0;
sub validAuth {
  ### always return vaid here. authtest.pl now handles password tests ###
  return 1;
  $pwdTests++;
	my ($sid,$uid,$pw,$noskip)=@_;
  if ($dbUsers->{$sid}{lastAuthTest}>$authTestPeriod && !$noskip) {
    ## a successful auth test was performed in the last month, so assume it's still good ##
    my $d=$dbUsers->{$sid}{lastAuthTest}*-1;
    logger("$uid auth test succeeded $d days ago - skip test\n",1);
    return 1;
  }
  ## limit number of tests since they are sow and resetting too many at once kills the server ##
  if ($pwdTests>20) {
    return 1;
  }

  $r=`ldapsearch  -h $adm -D CN=$uid,$syncUserBase -w $pw 2>&1`;
  if ($r =~ /nvalid/) {
    logger("$uid $pw auth test failed\n",1); 
    return 0; 
  }
  else { 
    print DBMOD "update users set lastAuthTestSuccess=now() where uid='$uid';\n";
    logger("$uid auth test succeeded\n",1);
    return 1; 
  }
}

###
### log a message in the log file
###

sub adUsers {
  my %adUsers=();
  ### Get a dump of the current AD users ###
  unless ($nodump) {
    `ssh administrator\@$adm "perl /addump.pl"`;
    `scp administrator\@$adm:/addump.csv $path`;
  }
  open (F,"<$path/addump.csv");
  @lines=<F>;
  close(F);
  shift(@lines);
  my $head=shift(@lines);
  $head=substr($head,0,-2);
  my @fields=split(/\|/,$head);
  my %sids=(); #used to check for duplicate student IDs in AD
  my $sidi=-1;
  for my $i (0 .. $#fields) {
    $fields[$i]=substr($fields[$i],1,-1);
    if ($fields[$i] eq $adUsersPK) {$sidi=$i;}
  }
  foreach my $line (@lines) {
    $line=substr($line,0,-2);
    my @vals=split(/\|/,$line);
    my $dn=$vals[0];
    $dn =~ /CN=([\w\d]+)/;
    $uid=$1;
    ## check for duplicate student ID ##
    if (substr($vals[$sidi],1,-1)>0) {
      if (defined $sids{$vals[$sidi]}) {
        logger("Student ID $vals[$sidi] is duplicated for $sids{$vals[$sidi]} and $uid\n",3);}
      else {$sids{$vals[$sidi]}=$uid;}
    }

    ## set values ##
    for my $i (0 .. $#fields) {$adUsers{$uid}{$fields[$i]}=substr($vals[$i],1,-1);}
    if (($adUsers{$uid}{userAccountControl} & 2)==2) {$adUsers{$uid}{disabled}=1;} else {$adUsers{$uid}{disabled}=0;}

    my @groups=split(/\;/,$adUsers{$uid}{memberOf});
    foreach my $group (@groups) {
      $group =~ /CN=([\w\d]+)/;
      my $cn=$1;
      $adUsers{$uid}{groups}{$group}=$cn;
    }
    ## trim uid to primary if ad record has two ##
    if ($adUsers{$uid}{uid} ne $uid) { 
      $adUsers{$uid}{uid}=$uid;
    }
  }
  return \%adUsers;
}

sub getUniqueAttrs {
	my %u=();
	$results= ldapSearch($userBase,'objectClass=user','uid uidNumber');
	my %nums=();
  ### build list of all uids and uidNumbers in AD
	foreach my $dn (keys %$results) {
		$u{uidNumbers}{$results->{$dn}{uidNumber}[0]}=1;
    for my $cnt (0 .. $#{$results->{$dn}{uid}}) {
		  $u{uids}{$results->{$dn}{uid}[$cnt]}=1;
    }
	}
  ### build list of 2000 free uidNumbers
	my $num=doQuery({query=>'select max(uidnumber) from users where uidNumber>999998 and uidNumber<2000000'});
  $num=$num->[0][0]+1;
	my $cnt=0;
	while ($cnt<5000) {
		unless (defined $nums{$num}) {
			push(@{$u{freeUidNumbers}},$num);
			$cnt++;
		}
		$num++;
	}
	return \%u;
}

sub ldapSearch {
	my ($base,$filter,$attrs)=@_;
	`ldapsearch -x -LLL -E pr=200/noprompt -h $adm -s sub -b $base -D $ad_admin_dn -w $ad_admin_pw "($filter)" $attrs > /tmp/ldapresults`;
	open (F,'</tmp/ldapresults');
	my @lines=<F>;
	close(F);
	my %r=();
	my $dn=undef;
	my $attr=undef;
	foreach my $line (@lines) {
		$attr=undef;
		$line =~ /(\S+?):\s([\s\S]+?)\n/;
		$attr=$1;
		$val=$2;
		if ($attr) {
			if ($attr eq 'dn') {$dn=$val;}
			push(@{$r{$dn}{$attr}},$val);
		}
	}
	return \%r;
}

###
### attempt to generate a unique uid from student name and gradYear
### if none of: ffllll##, ffflll##, ffffll##, fflll###
### are free, then generate error and move on to next student, requiring manual intervention
###
sub uniqueUid {
  my ($sid)=@_;
  my $uids=$uniqueAttrs->{uids};
  my $uid='';
  #make first and last names lowercase with nothing but letters
  my $fn=$dbUsers->{$sid}{firstName};
  my $ln=$dbUsers->{$sid}{lastName};
  $fn =~ s/\W//g;
  $ln =~ s/\W//g;
  $fn=lc($fn);
  $ln=lc($ln);
  my $suffix=$dbUsers->{$sid}{gradYear};
  #try first 2,3, or 4 of first name with first 4,3 or 2 of last name respectively and return if free
  for my $i (2 .. 4) {
    $uid=substr($fn,0,$i).substr($ln,0,6-$i).$suffix;
    unless (ciDefined ($uids,$uid)) {
      $uniqueAttrs->{uids}{$uid}=1;
      return $uid;
    }
  }
  my $i=0;
  #try first 2 of first, first 3 of last and a number (before the grad year) until one is free
  while (ciDefined ($uids,$uid) && $i<10) {
    $uid=substr($uid,0,5).$i.$suffix;
    $i++;
  }
  unless (ciDefined ($uids,$uid)) {
    $uniqueAttrs->{uids}{$uid}=1;
    return $uid;
  }
  # at this point, give up. Return null uid, resulting in no creation of student account
  logger("No Free UID found for student: $sid $fn $ln\n",3);
  return undef;
}

sub uidMatchesName {
  my ($args)=@_;
  for my $i (2 .. 4) {
    if (lc($args->{uid}) eq lc(substr($args->{firstName},0,$i).substr($args->{lastName},0,6-$i).$args->{gradYear})) {return 1;}
  }
  return 0;
}

sub uniqueUidNumber {
        return pop @{$uniqueAttrs->{freeUidNumbers}};
}

sub ciDefined {
        # case-insensitive check for defined hash key
        my ($hash,$key)=@_;
        foreach my $k (keys %$hash) {
                if (lc($k) eq lc($key)) {return 1;}
        }
        return 0;
}

sub xxxrenameUser {
  ### this is currently not used - might never be since students don't expect their uids to change
  my ($user)=@_;
  unless (uidMatchesName($user)) {
    logger("Rename $sid $user->{firstName} $user->{lastName}: Was $user->{uid} ",2);
    my $uid=$user->{uid};
    $user->{uid}='';
    $user->{uid}=uniqueUid($uniqueAttrs,$user);
    logger("Now $user->{uid}\n",2);
    $user->{dn}="CN=$user->{uid},$syncUserBase";
    $user->{mail}="$user->{uid}\@$mailDomain";
    $user->{name}=$user->{uid};
    $user->{sAMAccountName}=$user->{uid};
    $user->{userPrincipalName}="$user->{uid}\@$domain";
  	my $gr=substr($user->{uid},-2);
    $user->{unixHomeDirectory}="/Users/Students/$gr/$user->{uid}";
    $user->{cn}=$user->{uid};
    print ADREN "admod_path -b \"CN=$uid,$syncUserBase\" -unsafe -rename \"$user->{uid}\"\n";
  }
  $user->{displayName}="$user->{firstName} $user->{lastName}";
}

sub enableStudent {
  my ($sid)=@_;
  my $uid=$dbUsers->{$sid}{uid};
  #make sure set to disabled first
  disableStudent($uid);
  #then enable
  $adUsers{$uid}{userAccountControl}+=2;
  $adUsers{$uid}{enabled}=1;
}

sub disableStudent {
  my ($uid)=@_;
  $adUsers{$uid}{userAccountControl}=$adUsers{$uid}{userAccountControl}-($adUsers{$uid}{userAccountControl} & 2);
  $adUsers{$uid}{enabled}=0;
}

###
### Make sure a user profile is present and has the correct folders and permissions
### If folders exist in place of symlinks, move files to the linked folders (avoiding overwrite) and replace wrong folders with symlinks
###
sub checkProfile {
  my ($sid)=@_;
  my $uid=$dbUsers->{$sid}{uid};
  my $path=$dbUsers->{$sid}{profileFolderPath};
  my $uidNumber=$dbUsers->{$sid}{uidNumber};
  ### Create profile folder if it wasn't previously there
  unless (-d $path) {
    print FSMOD "if [ ! -d $path ]; then\ncp -R ./profileFolderSkel $path\nfi\nchown -R $uidNumber $path\nchmod -R 700 $path\n";
    if ($dbUsers->{$sid}{isNew}) {
      logger({email=>"Make profile for $uid at $path"});
    }
    else {
      logger({email=>"!!! user $uid profile $path was not present. Profile created, but manual restore of files might be required"});
    }
  }
  else {
    foreach my $folder (@profileFolders) {
      unless (-d "$path/$folder") {
        print FSMOD "mkdir $path/$folder\nchown $uidNumber $path/$folder\nchmod 700 $path/$folder\n";
#        logger ({email=>"!!! user $uid was missing folder $folder in path $path - manual restore of files might be required"});
        logger({sid=>$sid,log=>'profileSubfolderMissing',detail=>"$uid profile $path was not present."});
      }
    }
    foreach my $symlink (@profileSymlinks) {
      my ($link,$target)=%$symlink;
      unless (-l "$path/$link") {
        if (-d "$path/$link") {
          logger({detail=>"$path/$link not found to be a symlink"});
=pod
        ### Get and sanity-check absolute paths for link and target to feed to moveFiles ###
        $link=~/([\s\S]+)\/([^\/]+)/;
        my $linkPath=$1;
        my $linkName=$2;
        unless ($linkName) {$linkName=$link; $linkPath='';}
        print "lp='$linkPath'  ln='$linkName'\n";
        $folder=~/([\s\S]+)\/([^\/]+)/;
        #$folder =~ /(\.+\/)*([^\/]+\/?)+/;
        my $folderPath=$1;
        my $folderName=$2;
        unless ($folderName) {$folderName=$folder; $folderPath='';}
        print "fp='$folderPath'  fn='$folderName'\n";
        moveFiles("$path/$link","$path/$linkPath/$folderPath");
=cut
        }
        $link =~ s/\s/\\ /g;
        $target =~ s/\s/\\ /g;
  ### enable this when ready to start making symlinks on existing files
        #logger({detail=>"ln -s $target $path/$link"});
        #print FSMOD "ln -s $target $path/$link\n";
      }
    }
    #and verify folder permissions
    $perm=`ls -ld $path | awk '{print \$3}'`;
    chomp($perm);
    unless ("$perm" eq "$uidNumber") {
      print FSMOD "chown -R $uidNumber $path\n";
    }
  }
}

##
### Move files from $src to a new, unique subdirectory in $dst
###
sub moveFiles {
#### DO NOT ENABLE THIS UNTIL IT IS FIXED AND TESTED TO BE SAFE ###
=pod
  my ($src,$dst,$uid)=@_;
  my $subFolder='windowsFiles';
  my $c=0;
  while (-d "$dst/$subFolder") {
    $c++;
    $subFolder="windowsFiles$c";
  }
  print "mkdir $dst/$subfolder\nchown $uid $dst/$subFolder\nchmod 700 $dst/$subFolder\nmv $src/* $dst/$subfolder\nrm -R $src\n";
=cut
}

###
### Process a log message
### usage: logger({sid=>$sid,log=>'loggerKey',attr=>'attr',old=>$oldVal,new=>$newVal,msg=>'additional log message',email=>'additional email message'});
### a simple log file or email message may be added by passing values for 'email' or 'detail'
### sid and log are required for use of a defined logger - other arguments are optional, but may be expected by the logger
###

sub logger {
  my ($args)=@_;
  ## if this is for a user, flag as logged so log output will be generated
  if (defined $args->{sid}) {
    $dbUsers->{$args->{sid}}{logged}=1;
  }
  my $email='';
  my $detail='';
  my $uid='';
  ## if this is for a user and logger, process
  if (defined $args->{sid} && $args->{log} && defined $loggers{$args->{log}}) {
    my $sid=$args->{sid};
    my $logger=$loggers{$args->{log}};
    $uid=$dbUsers->{$sid}{uid};
    $detail="$args->{log}: ";
    ## increment count for this type of change
    if (defined $logger->{count}) {
      $counts{$logger->{count}}++;
      $dbUsers->{$sid}{modified}=1;
    }
    if (defined $logger->{email}) {$email="$logger->{email} ";}
    if (defined $args->{email}) {$email.="--$args->{email}\n";} elsif ($email) {$email.="\n";}
    $detail.="$email";
    if (defined $logger->{changeLogAttr}) {
      if (defined $args->{attr}) {$logger->{changeLogAttr}=$args->{attr};}
      my $desc="$logger->{changeLogAttr}: from \"$args->{old}\" to \"$args->{new}\" ; ";
      $dbUsers->{$sid}{changes}{description}.=$desc;
      $detail.="$desc\n";
      $email.="$desc\n";
    }
    if (defined $logger->{changeLogField}) {
      $dbUsers->{$sid}{changes}{$logger->{changeLogField}[0]}=$logger->{changeLogField}[1];
    }
    if (defined $logger->{detail}) {
      $detail.="$logger->{detail}\n";
    }
    ## increment count for a failure to change
    if (defined $logger->{failCount}) {
      $failCounts{$logger->{failCount}}++;
    }
    ## increment count for a warning
    if (defined $logger->{warningCount}) {
      $warningCounts{$logger->{warningCount}}++;
      $logger->{warnings}.="$args->{detail}\n";
    }
  }
  else {
    if (defined $args->{email}) {
      $email.="--$args->{email}\n";
      $detail.="$email";
    }
  }
  if (defined $args->{detail}) {
    $detail.="$args->{detail}\n";
  }
  ## generate output
  if ($detail) {
    print L "$uid $detail";
  }
  if ($email) {
    if ($uid) {$email="$uid $email";}
    if ($args->{log}) {$email="$args->{log}: $email";}
    $rpt.=$email;
  }
}

sub DBInit {
  my ($args)=@_;
  $dbh=DBI->connect("DBI:mysql:$args->{db}",$args->{user},$args->{pwd});
}

sub doQuery {
  my ($args)=@_;
  my $query=$args->{query};
  my $key=$args->{key};
  if ($key) {
    return $dbh->selectall_hashref($query,$key);
  }
  elsif ($query =~ /^select/i) {
    return $dbh->selectall_arrayref($query);
  }
  else {
    my $sth=$dbh->prepare($query);
    return $sth->execute();
  }
}
