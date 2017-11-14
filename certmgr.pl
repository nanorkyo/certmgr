#!/usr/bin/perl
use strict;
use integer;
use constant DBVER       => 2017114101;
use constant CONFIGFILES => qw(.certmgrrc  $ENV{HOME}/.certmgrrc  /etc/certmgrrc);

use DBI;
use App::Rad;	#qw(debug);
use IO::File;
use IO::Handle;
use IPC::Open2;
use File::Temp;
use Data::Dumper;
use File::Basename;

use POSIX "strftime";
use Digest::SHA "sha256_base64";
use Getopt::Long qw(:config posix_default no_ignore_case gnu_compat);

App::Rad->run;

sub setup {
	my $c = shift;
	$c->register_commands( {
		init     => "Init SSL Certificates Repogitory.",
		list     => "List common names and/or certificates",
		generate => "Generate a CSR(and KEY)",
		import   => "Import CSR/KEY/CRT",
		export   => "Export CSR/KEY/CRT",
		info     => "Display CSR/KEY/CRT information",
	});

	my $config;
	GetOptions ("config|c=s" => \$config);	# XXX: Do error handling #

	my $config;
	if(  $config eq ""  )  {
		foreach  (  CONFIGFILES  )  {
			next  unless(  -r  );
			$config = $_;
			last;
		}
	}
	$c->stash->{Config} = $config;
} # setup #

sub pre_process {
	my $c = shift;
	if(  defined $c->stash->{Config}  )  {
		$c->load_config($c->stash->{Config});
	}

	my $dbsrc  = $c->config->{CertRepo} || "";
	my $dbuser = $c->config->{UserName} || "";
	my $dbpass = $c->config->{PassWord} || "";
	if(  $dbsrc eq ""  )  {
		die "setup your certmgrrc file.";
	} # NOT REACHABLE #
	else  {
		umask 0077;
		my $dbh = eval {
			DBI->connect($dbsrc, $dbuser, $dbpass, {AutoCommit => 1, RaiseError => 1});
	   	};
		if(  $@  )  {
			return sprintf("Database connect error(%s): %s", $dbsrc, $@);
		}  # NOT REACHABLE #

		$dbh->do("PRAGMA foreign_keys = ON;");

		my $dbver;
		if(  $dbh->selectrow_array("SELECT EXISTS (SELECT * FROM sqlite_master WHERE type = 'table' AND name = 'config')")  )  {
			$dbver = $dbh->selectrow_array("SELECT version FROM config WHERE is_active = 't'");
		}  else  {
			$dbver = 0;
		}
		$c->stash->{DBH}    = $dbh;
		$c->stash->{DBSRC}  = $dbsrc;
		$c->stash->{DBUSER} = $dbuser;
		$c->stash->{DBPASS} = $dbpass;
		$c->stash->{DBVER}  = $dbver;
	}
} # pre_process #

sub readfile($) {
	my $file = shift;
	my $fh = new IO::File($file, "r")  or  die sprintf("cannot read file(%s): %s", $file, $!);
	my $data = join("", <$fh>);
	close($fh);
	return $data;
} # readfile

sub refilename($$$$$$$$) {
	my($filename, $cn, $startyyyy, $startmm, $startdd, $endyyyy, $endmm, $enddd) = @_;
	   $filename =~ s/%CN%/$cn/g;
	   $filename =~ s/%SYYYY%/$startyyyy/g;
	   $filename =~ s/%SMM%/$startmm/g;
	   $filename =~ s/%SDD%/$startdd/g;
	   $filename =~ s/%EYYYY%/$endyyyy/g;
	   $filename =~ s/%EMM%/$endmm/g;
	   $filename =~ s/%EDD%/$enddd/g;
	return $filename;
} # refilename

sub filtcmd($@) {
	my $data   = shift;
	my @cmd    = @_;
	my $stdin  = new IO::Handle();
	my $stdout = new IO::Handle();
	my $pid    = open2($stdout, $stdin, @cmd);	# XXX: Do error handling #
	   $stdin->print($data);
	   $stdin->close();
	my $output = join("", <$stdout>);
	   $stdout->close();
	waitpid($pid, 0);

	return $output;
} # filtcmd

sub openssl_x509_subject($) {
	my $pem  = shift;
	my $dist = filtcmd($pem, qw{openssl x509 -noout -subject -issuer});

	my %dist;
	while(  $dist =~ m{^((?:subject)|(?:issuer))=\s*(/.+)$}mg  )  {
		$dist{$1} = $2;
	}
	return wantarray ? ($dist{subject}, $dist{issuer}) : $dist{subject};
} # openssl_x509_subject

sub openssl_req_subject($) {
	my $pem  = shift;
	my $subj = filtcmd($pem, qw{openssl req -noout -subject});
	chomp($subj);
	$subj =~ s/^subject=\s*//;
	return $subj;
} # openssl_req_subject

sub openssl_req_pubkey($) {
	my $pem    = shift;
	my $pubkey = filtcmd($pem, qw{openssl req -noout -pubkey});
	my $pubder = filtcmd($pubkey, qw{openssl pkey -pubin -outform der});
	return sha256_base64($pubder);
} # openssl_req_pubkey

sub openssl_x509_pubkey($) {
	my $pem    = shift;
	my $pubkey = filtcmd($pem, qw{openssl x509 -noout -pubkey});
	my $pubder = filtcmd($pubkey, qw{openssl pkey -pubin -outform der});
	return sha256_base64($pubder);
} # openssl_x509_pubkey

sub openssl_pkey_pubkey($) {
	my $pem    = shift;
	my $pubder = filtcmd($pem, qw{openssl pkey -pubout -outform der});
	return sha256_base64($pubder);
} # openssl_pkey_pubkey

sub openssl_x509_date($) {
	my $pem    = shift;
	my $date   = filtcmd($pem, qw{openssl x509 -noout -startdate -enddate});

	my %date;
	while(  $date =~ m{^not((?:Before)|(?:After))=\s*(\S.+)$}mg  )  {
		my($way, $timestamp) = ($1, $2);
		if(  $timestamp =~ m/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{1,2}):(\d{1,2}):(\d{1,2})\s+(\d{4})\s+GMT$/  )  {
			$date{$way} = sprintf("%04d-%02d-%02d %02d:%02d:%02d",
				$6, {Jan => 1, Feb => 2, Mar => 3, Apr => 4, May => 5, Jun => 6, Jul => 7, Aug => 8, Sep => 9, Oct => 10, Nov => 11, Dec => 12}->{$1}, $2,
				$3, $4, $5);
		}  else  {
			die sprintf("[BUG] openssl x509 -noout -stadate -enddate returns unexpected timestamp: %s", $timestamp);
		}
	}
	return ($date{"Before"}, $date{"After"});
} # openssl_x509_date

sub get_cn_from_subject($) {
	my $subj = shift;
	if(  $subj =~ m|^/.*(?<=/)[Cc][Nn]=([^/]+)|  )  {
		return wantarray ? ($1, $subj)    : $1;
	} # NOT REACHABLE #
	elsif(  $subj =~ m|^/|  )  {
		return wantarray ? (undef, $subj) : undef;
	} # NOT REACHABLE #
	else  {
		return wantarray ? ($subj, undef) : $subj;
	} # NOT REACHABLE #
} # get_cn_from_subject

sub get_subject_from_cn($$) {
	my($dbh, $cn) = @_;
	return $dbh->selectrow_array(q{SELECT subject FROM certificate INNER JOIN sslcsr USING(certid) WHERE commonname = ? ORDER BY created DESC LIMIT 1}, {}, $cn);
} # get_subject_from_cn

sub init {
	my $c   = shift;
	my $dbh = $c->stash->{DBH};

	my $dbver = $c->stash->{DBVER};
	if(  0 < $dbver && $dbver < DBVER  )  {
		return sprintf("Upgrade your CertRepo(current=%d, latest=%d)", $dbver, DBVER);
	} # NOT REACHABLE #
	elsif(  $dbver >= DBVER  )  {
		return sprintf("CertRepo already initialized (current=%d)", $dbver);
	} # NOT REACHABLE #

	# config table #
	$dbh->do(q{
		CREATE TABLE IF NOT EXISTS config (
			version		INTEGER		NOT NULL,
			is_active	BOOLEAN		NOT NULL
		);
	});
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS config_active_idx ON config(is_active) WHERE is_active = 't'");
	$dbh->do("INSERT INTO config (version, is_active) VALUES (?, 't')", {}, DBVER);

	# plugins table #
	$dbh->do(q{
		CREATE TABLE IF NOT EXISTS plugins (plugin_name TEXT NOT NULL, plugin_version INTEGER NOT NULL);
	});
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS plugins_plugin_name_idx ON plugins(plugin_name);");

	# certificate table #
	$dbh->do(q{
		CREATE TABLE IF NOT EXISTS certificate (
			certid		INTEGER		NOT NULL PRIMARY KEY AUTOINCREMENT,
			commonname	TEXT		NOT NULL,
			is_active	BOOLEAN		NOT NULL,
			is_marked	BOOLEAN		NOT NULL,
			created		TIMESTAMP	NOT NULL DEFAULT (DATETIME('NOW', 'LOCALTIME')) -- LOCAL
		);
	});
	$dbh->do("CREATE INDEX IF NOT EXISTS certificate_commonname_idx ON certificate(commonname)");

	# sslcrt table #
	$dbh->do(q{
		CREATE TABLE IF NOT EXISTS sslcrt (
			certid		INTEGER		NOT NULL,
			subject		TEXT		NOT NULL,
			issuer		TEXT		NOT NULL,
			startdate	TIMESTAMP	NOT NULL,	-- UTC
			enddate		TIMESTAMP	NOT NULL,	-- UTC
			crttext		TEXT		NOT NULL,
			hashkey		TEXT		NOT NULL,
				FOREIGN KEY(certid) REFERENCES certificate(certid)
		);
	});
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS sslcrt_certid_idx  ON sslcrt(certid)");
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS sslcrt_hashkey_idx ON sslcrt(hashkey)");

	# sslcsr table #
	$dbh->do(q{
		CREATE TABLE IF NOT EXISTS sslcsr (
			certid		INTEGER		NOT NULL,
			subject		TEXT		NOT NULL,
			csrtext		TEXT		NOT NULL,
			hashkey		TEXT		NOT NULL,
				FOREIGN KEY(certid) REFERENCES certificate(certid)
		);
	});
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS sslcsr_certid_idx  ON sslcsr(certid)");
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS sslcsr_hashkey_idx ON sslcsr(hashkey)");

	# sslkey table #
	$dbh->do(q{
		CREATE TABLE IF NOT EXISTS sslkey (
			certid		INTEGER		NOT NULL,
			keytext		TEXT		NOT NULL,
			hashkey		TEXT		NOT NULL,
				FOREIGN KEY(certid) REFERENCES certificate(certid)
		);
	});
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS sslkey_certid_idx ON sslkey(certid)");
	$dbh->do("CREATE UNIQUE INDEX IF NOT EXISTS sslkey_hashkey_idx ON sslkey(hashkey)");

	return sprintf("CertRepo initialized, done (current=%d)", DBVER);
} # init

sub get_plugin_version($$) {
	my($dbh, $name) = @_;
	return  $dbh->selectrow_array("SELECT version FROM plugins WHERE plugin_name = ?", {}, $name) || 0;
} # get_plugin_version

sub generate {
	my $c   = shift;
	my $dbh = $c->stash->{DBH};

	init($c)  if(  $c->stash->{DBVER} == 0  );

	$c->getopt("mark|m", "unmark|u", "type|t=s", "sign|s=s", "sans|san=s", "ocsp-must-staple");	# XXX: Do error handle #

	my $cn;
	my($csr, $key);
	my $subj     = shift(@{$c->argv})  || "";
	my $type     = $c->options->{type} || "";
	my $sign     = $c->options->{sign} || "";
	my @sans     = split(/,/, $c->options->{sans});
	my $ocspmust = $c->options->{"ocsp-must-staple"};

	my $dmark = undef;
	$dmark = 1  if(  $c->config->{DefaultMarked} =~ m/(?:[Yy][Ee][Ss])|(?:[Tt][Rr][Uu][Ee])|(?:[Oo][Nn])|(?:1)/  );
	$dmark = 0  if(  $c->config->{DefaultMarked} =~ m/(?:[Nn][Oo])|(?:[Ff][Aa][Uu][Ll][Tt])|(?:[Oo][Ff][Ff])|(?:0)/  );
	$dmark = 1  if(  !defined $dmark  );

	my $mark  = $dmark ? ($c->options->{unmark} ? "f" : "t") : ($c->options->{mark} ? "t" : "f");

	($cn, $subj) = get_cn_from_subject($subj);
	if(  defined $cn  && !defined $subj  )  {
		$subj = get_subject_from_cn($dbh, $cn);
	}
	if(  !defined $cn  )  {
		return sprintf("%s [-m|<-t sigalgo> <-s macalgo>] [/subject]: CN(CommonName) required in subject", $c->cmd);
	} # NOT REACHABLE #
	elsif(  !defined $subj  )  {
		return sprintf("%s [-m|<-t sigalgo> <-s macalgo>] [/subject]: subject required", $c->cmd);
	} # NOT REACHABLE #

	$type = "rsa:2048"  if(  $type eq ""  );
	if(  $type ne "rsa:1024"   && $type ne "rsa:2048"  && $type ne "rsa:3072"  && $type ne "rsa:4096"
	  && $type ne "prime256v1" && $type ne "secp256r1" && $type ne "secp384r1" && $type ne "secp521r1"  )  {
		return sprintf("%s not supported certificate type(%s)", $c->cmd, $type);
	} # NOT REACHABLE #

	$sign = "sha256"    if(  $sign eq ""  );
	if(  $sign ne "sha" && $sign ne "sha1" && $sign ne "sha256" && $sign ne "sha384" && $sign ne "sha512"  )  {
		return sprintf("%s not supported certificate signature(%s)", $c->cmd, $sign);
	} # NOT REACHABLE #

	printf "cn:               %s\n", $cn;
	printf "subject:          %s\n", $subj;
	printf "sans:             %s\n", join(", ", @sans);
	printf "type:             %s\n", $type;
	printf "sign:             %s\n", $sign;
	printf "markable:         %s\n", ($mark ? "Yes" : "No");
	printf "OCSP Must Staple: %s (%s fail)\n", ( $ocspmust ? ("Yes", "hard") : ("No", "soft") );

	my $csrfile = new File::Temp(UNLINK => 0);
	   $csrfile->unlink_on_destroy(1);
	my $keyfile = new File::Temp(UNLINK => 0);
	   $keyfile->unlink_on_destroy(1);
	my $confile = new File::Temp(UNLINK => 0);
	   $confile->unlink_on_destroy(1);

	   $confile->print("[distinguished_name]\n");
	   $confile->print("[req]\n");
	   $confile->print("distinguished_name = distinguished_name\n");

	if(  @sans || $ocspmust  )  {
		$confile->print("req_extensions     = req_extensions\n");
		$confile->print("[req_extensions]\n");

		if(  @sans  )  {
			$confile->printf("subjectAltName = %s\n", join(", ", map { "DNS:$_" } @sans));
		}
		if(  $ocspmust  )  {
			$confile->print("1.3.6.1.5.5.7.1.24=DER:30:03:02:01:05\n");
		}
	}

	if(  $type =~ /rsa:/  )  {
		system("openssl", "req", "-new", "-newkey", $type, "-$sign", "-nodes", "-subj", $subj, "-out", $csrfile->filename, "-keyout", $keyfile->filename, "-config", $confile->filename);
	} elsif(  $type =~ /prime256v1|secp256r1|secp384r1|secp521r1/  )  {
		my $ecfile = new File::Temp(UNLINK => 0);
		   $ecfile->unlink_on_destroy(1);
		system("openssl", "ecparam", "-name", $type, "-param_enc", "named_curve", "-out", $ecfile->filename);
		system("openssl", "req", "-new", "-newkey", "ec:$ecfile", "-$sign", "-nodes", "-subj", $subj, "-out", $csrfile->filename, "-keyout", $keyfile->filename, "-config", $confile->filename);
		   $ecfile->close();
	}

	$csr = join("", <$csrfile>);
	$key = join("", <$keyfile>);

	close($csrfile);
	close($keyfile);

	my $csrhash = openssl_req_pubkey($csr);
	my $keyhash = openssl_pkey_pubkey($key);

	my $certid;
	$dbh->begin_work;
	$dbh->do(q{INSERT INTO certificate (commonname, is_active, is_marked) VALUES (?, 'f', ?)}, {}, $cn, $mark);
	$certid = $dbh->selectrow_array("SELECT last_insert_rowid() FROM certificate");
	$dbh->do(q{UPDATE certificate SET is_marked = 'f' WHERE commonname = ? AND certid <> ? AND is_marked = 't'}, {}, $cn, $certid)  if(  $mark eq "t"  );
	$dbh->do(q{INSERT INTO sslcsr (certid, subject, csrtext, hashkey) VALUES (?, ?, ?, ?)}, {}, $certid, $subj, $csr, $csrhash);
	$dbh->do(q{INSERT INTO sslkey (certid, keytext, hashkey) VALUES (?, ?, ?)}, {}, $certid, $key, $keyhash);
	$dbh->commit;
	$dbh->disconnect;

	print $csr;

	return sprintf("%s successfully: certid=%d, subject=%s", $c->cmd, $certid, $subj);
} # generate #

sub max($$) { return $_[0] > $_[1] ? $_[0] : $_[1]; }
sub min($$) { return $_[0] < $_[1] ? $_[0] : $_[1]; }
sub list {
	my $c    = shift;
	my $dbh  = $c->stash->{DBH};

	init($c)  if(  $c->stash->{DBVER} == 0  );

	$c->getopt("order|o=s@", "reverse|r");		# XXX: Do error handle #

	my $cn    = shift @{$c->argv};
	my @order = $c->options->{order} ? @{$c->options->{order}} : "certid";
	my $dir   = $c->options->{reverse} ? "DESC" : "ASC";

	my @_order;
	foreach (  map { split /,/ } @order  )  {
		push @_order, ("commonname"                      )  if(  $_ eq "cn"     || $_ eq "common"    || $_ eq "commonname"  );
		push @_order, ("sslcrt.subject", "sslcsr.subject")  if(  $_ eq "subj"   || $_ eq "subject"                          );
		push @_order, ("issuer"                          )  if(  $_ eq "issuer"                                             );
		push @_order, ("startdate"                       )  if(  $_ eq "start"  || $_ eq "startdate"                        );
		push @_order, ("enddate"                         )  if(  $_ eq "end"    || $_ eq "endate"    || $_ eq "enddate"     );
		push @_order, ("is_active"                       )  if(  $_ eq "act"    || $_ eq "active"                           );
		push @_order, ("is_marked"                       )  if(  $_ eq "mark"                                               );
	}
	my $order = @_order ? join(", ", @_order) : "certid";

	my $list = $dbh->selectall_arrayref(qq{
		SELECT certid, commonname, COALESCE(sslcrt.subject, sslcsr.subject),
		       CASE WHEN sslcrt.certid IS NOT NULL THEN 'CRTIN' ELSE 'nocrt' END,
		       CASE WHEN sslcsr.certid IS NOT NULL THEN 'CSRIN' ELSE 'nocsr' END,
		       CASE WHEN sslkey.certid IS NOT NULL THEN 'KEYIN' ELSE 'nokey' END,
		       CASE WHEN is_active = 't' THEN 'ACT'  ELSE 'inact'  END,
		       CASE WHEN is_marked = 't' THEN 'MARK' ELSE 'unmark' END,
		       COALESCE(date(startdate), 'N/A'), COALESCE(date(enddate), 'N/A') --, created
		  FROM certificate
		  LEFT JOIN sslcrt USING(certid)
		  LEFT JOIN sslcsr USING(certid)
		  LEFT JOIN sslkey USING(certid)
		 ORDER BY $order $dir
	});
	my @column;
	foreach ( @$list ) {
		for( my $i = 0; $i < @$_; $i++ )  {
			$column[$i] = min(max(length($_->[$i]), $column[$i]), ($i == 1 ? 64 : 32));
		}
	}
	my @format;
	foreach( @column ) {
		push @format, sprintf("%%-%d.%ds", $_, $_);
	}
	foreach ( @$list ) {
		printf(join(" ", @format, "\n"), @$_);
	}
} # list #

sub import_csr($$$$) {
	my($c, $dbh, $csr, $mark) = @_;
	my $csrhash = openssl_req_pubkey($csr);
	my $subj    = openssl_req_subject($csr);
	my $cn      = get_cn_from_subject($subj);

	if(  $dbh->selectrow_array("SELECT EXISTS (SELECT * FROM sslcsr WHERE hashkey = ?)", {}, $csrhash)  )  {
		printf("%s ignored: cert=CSR, error=already imported, subject=%s\n", $c->cmd, $subj);
		return;
	} # NOT REACHABLE #

	$dbh->begin_work;

	my $certid = $dbh->selectrow_array(q{
		SELECT certid FROM sslcrt WHERE hashkey = ?
		 UNION
		SELECT certid FROM sslkey WHERE hashkey = ?
	}, {}, $csrhash, $csrhash);
	if(  !defined $certid  )  {
		$dbh->do("INSERT INTO certificate (commonname, is_active, is_marked) VALUES (?, 'f', ?)", {}, $cn, $mark);
		$certid = $dbh->selectrow_array("SELECT last_insert_rowid() FROM certificate");
	}  else  {
		if(  $mark eq "t"  )  {
			$dbh->do("UPDATE certificate SET is_marked = 't' WHERE certid = ?",                                         {},      $certid);
			$dbh->do("UPDATE certificate SET is_marked = 'f' WHERE commonname = ? AND certid <> ? AND is_marked = 't'", {}, $cn, $certid);
		}
	}
	$dbh->do("INSERT INTO sslcsr (certid, subject, csrtext, hashkey) VALUES (?, ?, ?, ?)", {}, $certid, $subj, $csr, $csrhash);

	$dbh->commit;

	printf("%s successfully: cert=CSR, subject=%s\n", $c->cmd, $subj);
	return;
} # import_csr

sub import_key($$$) {
	my($c, $dbh, $key) = @_;
	my $keyhash = openssl_pkey_pubkey($key);

	if(  $dbh->selectrow_array("SELECT EXISTS (SELECT * FROM sslkey WHERE hashkey = ?)", {}, $keyhash)  )  {
		my $subj = $dbh->selectrow_array("SELECT subject FROM sslkey LEFT JOIN sslcrt USING(certid) WHERE sslkey.hashkey = ?", {}, $keyhash);
		printf("%s ignored: cert=KEY, error=already imported, subject=%s\n", $c->cmd, $subj || "(null)");
		return;
	} # NOT REACHABLE #

	$dbh->begin_work;

	my $certid = $dbh->selectrow_array(q{
		SELECT certid FROM sslcrt WHERE hashkey = ?
		 UNION
		SELECT certid FROM sslcsr WHERE hashkey = ?
	}, {}, $keyhash, $keyhash);
	if(  !defined $certid  )  {
		$dbh->commit;
		printf("%s ignored: cert=KEY, error=couldn't be imported by no CSR/CRT found: hash=%s\n", $c->cmd, $keyhash);
		return;
	} # NOT REACHABLE #

	$dbh->do("INSERT INTO sslkey (certid, keytext, hashkey) VALUES (?, ?, ?)", {}, $certid, $key, $keyhash);

	$dbh->commit;

	printf("%s successfully: cert=KEY, certid=%d\n", $c->cmd, $certid);
	return;
} # import_key

sub import_crt($$$) {
	my($c, $dbh, $crt)   = @_;
	my $crthash      = openssl_x509_pubkey($crt);
	my($subj, $isue) = openssl_x509_subject($crt);
	my($start, $end) = openssl_x509_date($crt);
	my $cn           = get_cn_from_subject($subj);

	if(  $cn eq ""  )  {
		printf("%s ignored: cert=CRT, error=Non CommonName supported, subject=%s\n", $c->cmd, $subj);
		return;
	} # NOT REACHABLE #

	if(  $dbh->selectrow_array("SELECT EXISTS (SELECT * FROM sslcrt WHERE hashkey = ?)", {}, $crthash)  )  {
		printf("%s ignored: cert=CRT, error=already imported, subject=%s\n", $c->cmd, $subj);
		return;
	} # NOT REACHABLE #

	$dbh->begin_work;

	my $certid = $dbh->selectrow_array(q{
		SELECT certid FROM sslcsr WHERE hashkey = ?
		 UNION
		SELECT certid FROM sslkey WHERE hashkey = ?
	}, {}, $crthash, $crthash);
	if(  !defined $certid  )  {
		$dbh->do("INSERT INTO certificate (commonname, is_active, is_marked) VALUES (?, 't', 'f')", {}, $cn);
		$certid = $dbh->selectrow_array("SELECT last_insert_rowid() FROM certificate");
	}  else  {
		$dbh->do("UPDATE certificate SET is_active = 't' WHERE certid = ?", {}, $certid);
	}
	$dbh->do("INSERT INTO sslcrt (certid, subject, issuer, startdate, enddate, crttext, hashkey) VALUES (?, ?, ?, ?, ?, ?, ?)", {}, $certid, $subj, $isue, $start, $end, $crt, $crthash);

	$dbh->commit;

	printf("%s successfully: cert=CRT, subject=%s\n", $c->cmd, $subj);
	return;
} # import_crt

sub import {
	my $c    = shift;
	my $dbh  = $c->stash->{DBH};

	init($c)  if(  $c->stash->{DBVER} == 0  );

	$c->getopt("mark|m", "unmark|u");	# XXX: Do error handle #

	my $dmark = undef;
	$dmark = 1  if(  $c->config->{DefaultMarked} =~ m/(?:[Yy][Ee][Ss])|(?:[Tt][Rr][Uu][Ee])|(?:[Oo][Nn])|(?:1)/  );
	$dmark = 0  if(  $c->config->{DefaultMarked} =~ m/(?:[Nn][Oo])|(?:[Ff][Aa][Uu][Ll][Tt])|(?:[Oo][Ff][Ff])|(?:0)/  );
	$dmark = 1  if(  !defined $dmark  );

	my $mark  = $dmark ? ($c->options->{unmark} ? "f" : "t") : ($c->options->{mark} ? "t" : "f");

	foreach  my $file  ( @{$c->argv} )  {
		if(not  -r $file  )  {
			printf("%s ignored: error=no file found, file='%s'\n", $c->cmd, $file);
			next;
		} # NOT REACHABLE #

		my $fh = new IO::File($file, "r")   or  die sprintf("cannot read file(%s): %s", $file, $!);

		my($csr, $key, $crt, $header) = ("", "", "", "");
		while(  <$fh>  )  {
			if(  m|^-----\s*BEGIN\s+(CERTIFICATE\s+REQUEST)\s*-----$|  )  {
				$csr    = $_;
				$header = $1;
				next;
			}  # NOT REACHABLE #
			elsif(  m|^-----\s*BEGIN\s+(PRIVATE\s+KEY)\s*-----$|  )  {
				$key    = $_;
				$header = $1;
				next;
			}  # NOT REACHABLE #
			elsif(  m|^-----\s*BEGIN\s+(CERTIFICATE)\s*-----$| )  {
				$crt    = $_;
				$header = $1;
				next;
			} # NOT REACHABLE #

			$csr .= $_  if(  $csr ne ""  );
			$key .= $_  if(  $key ne ""  );
			$crt .= $_  if(  $crt ne ""  );

			if(  m|^-----END\s+\Q${header}\E\s*-----$|  )  {
				import_csr($c, $dbh, $csr, $mark)  if(  $csr ne ""  );
				import_key($c, $dbh, $key       )  if(  $key ne ""  );
				import_crt($c, $dbh, $crt       )  if(  $crt ne ""  );
				$csr    = "";
				$key    = "";
				$crt    = "";
				$header = "";
			}
		}

		close($fh);
	}

	$dbh->disconnect();

	return undef;
} # import

sub export_all($$$$) {
	my($c, $dbh, $basename, $basemode) = @_;
	my $fh = new File::Temp(DIR => dirname($basename), UNLINK => 1);

	my($ncsr, $nkey, $ncrt) = (0, 0, 0);

	my $certid;
	my $sth = $dbh->prepare("SELECT certid FROM certificate ORDER BY certid");
	   $sth->execute();
	   $sth->bind_columns(\$certid);

	while(   $sth->fetch  )  {
		my($subject, $issuer, $csrtext, $keytext, $crttext) = $dbh->selectrow_array(q{
			SELECT COALESCE(sslcrt.subject, sslcsr.subject), COALESCE(issuer, 'N/A'), csrtext, keytext, crttext
			  FROM certificate
			  LEFT JOIN sslcsr USING(certid) 
			  LEFT JOIN sslkey USING(certid) 
			  LEFT JOIN sslcrt USING(certid) 
			 WHERE certid = ?
		}, {}, $certid);

		$fh->printf("subject=%s\n", $subject)  if(  defined $subject  );
		$fh->printf("issuer =%s\n", $issuer)   if(  defined $issuer   );
		if(  defined $csrtext  )  {
			$fh->print($csrtext);
			$ncsr++;
		}
		if(  defined $keytext  )  {
			$fh->print($keytext);
			$nkey++;
		}
		if(  defined $crttext  )  {
			$fh->print($crttext);
			$ncrt++;
		}
		$fh->print("\n");
	}
	$sth->finish;

	chmod($basemode, $fh);
	rename($fh, $basename);

	$fh->close();

	printf("%s successfully: all certificate keys ware exported, file=%s, csr=%d, key=%d, crt=%d\n", $c->cmd, $basename, $ncsr, $nkey, $ncrt);
	return;
} # export_all

sub export_cert($$$$$$$$$@) {
	my($c, $dbh, $pubout, $pubmode, $keyout, $keymode, $chainout, $chainmode, $require_fullchain, @argv) = @_;

	foreach  my $argv  ( @argv )  {
		my $pubfh   = new File::Temp(DIR => dirname($pubout),   UNLINK => 1);
		my $keyfh   = new File::Temp(DIR => dirname($keyout),   UNLINK => 1);
		my $chainfh = new File::Temp(DIR => dirname($chainout), UNLINK => 1);

		my($sth, $certid, $cn);

		if(  $argv =~ /^\d+$/  )  {
			$certid = $argv;
			$cn     = $dbh->selectrow_array("SELECT commonname FROM certificate WHERE certid = ?", {}, $argv);
		}  else  {
			$certid = $dbh->selectrow_array("SELECT certid     FROM certificate WHERE commonname = ? AND is_marked = 't' ORDER BY is_active DESC LIMIT 1", {}, $argv);
			$cn     = $argv;
		}
	
		if(  !defined $certid || !defined $cn  )  {
			printf("%s ignored: cn=%s, certid=%s, error=no certificate found\n", $c->cmd, $cn || "(null)", $certid || "(null)");
			next;
		} # NOT REACHABLE #

		my $chaintext;
		my($crttext, $keytext, $issuer, $startyyyy, $startmm, $startdd, $endyyyy, $endmm, $enddd) = $dbh->selectrow_array(q{
			SELECT crttext, keytext, issuer,
			       strftime('%Y', startdate, 'localtime'), strftime('%m', startdate, 'localtime'), strftime('%d', startdate, 'localtime'), 
			       strftime('%Y', enddate,   'localtime'), strftime('%m', enddate,   'localtime'), strftime('%d', enddate,   'localtime')
			  FROM certificate
			  LEFT JOIN sslcrt USING(certid) 
			  LEFT JOIN sslkey USING(certid) 
			 WHERE certid = ?
		}, {}, $certid);
	
		if(  defined $crttext  )  {
			$pubfh->print($crttext);
		}
		if(  defined $keytext  )  {
			$keyfh->print($keytext);
		}

		while(  defined $issuer  )  {
			my $chaintext;
			($chaintext, $issuer) = $dbh->selectrow_array(q{
				SELECT crttext, issuer
				  FROM sslcrt
				 INNER JOIN certificate USING(certid)
				 WHERE subject = ? AND subject <> issuer AND is_active = 't'
			}, {}, $issuer);

			if(  defined $chaintext  )  {
				$pubfh->print($chaintext)    if(  $require_fullchain  );
				$chainfh->print($chaintext)
			}
		}

		my $_pubout   =  refilename($pubout,   $cn, $startyyyy, $startmm, $startdd, $endyyyy, $endmm, $enddd);
		my $_keyout   =  refilename($keyout,   $cn, $startyyyy, $startmm, $startdd, $endyyyy, $endmm, $enddd);
		my $_chainout =  refilename($chainout, $cn, $startyyyy, $startmm, $startdd, $endyyyy, $endmm, $enddd);

		chmod($pubmode,   $pubfh);
		chmod($keymode,   $keyfh);
		chmod($chainmode, $chainfh);
		rename($pubfh,   $_pubout)    if(  $pubfh->tell() > 0    );
		rename($keyfh,   $_keyout)    if(  $keyfh->tell() > 0    );
		rename($chainfh, $_chainout)  if(  $chainfh->tell() > 0  );

		# Never close() before rename().
		$pubfh->close();
		$keyfh->close();
		$chainfh->close();

		printf("%s successfully: commonname='%s'(certid=%d), crtfile=%s, keyfile=%s, chainfile=%s\n", $c->cmd, $cn, $certid, $_pubout, $_keyout, $_chainout);
	}

	return;
} # export_cert

sub export {
	my $c    = shift;
	my $dbh  = $c->stash->{DBH};

	init($c)  if(  $c->stash->{DBVER} == 0  );

	$c->getopt("basename|base|back|backup|b=s", "pubout=s", "keyout=s", "chainout=s", "fullchain|full-chain|recursive|r", "all|a");

	my $reuquire_all      = $c->options->{all};
	my $require_fullchain = $c->options->{fullchain};
	my $basename   = $c->options->{basename} ? $c->options->{basename} : ($reuquire_all ? strftime("export-%Y%m%d%H%M%S.BAK", localtime) : $c->config->{BaseName} || "%CN%");
	my $basemode   = 0400;	# for backup use #
	my $pubout     = $c->options->{pubout}   ? $c->options->{pubout}   : "${basename}.crt";
	my $pubmode    = 0444;
	my $keyout     = $c->options->{keyout}   ? $c->options->{keyout}   : "${basename}.key";
	my $keymode    = 0400;
	my $chainout   = $c->options->{chainout} ? $c->options->{chainout} : "${basename}.chain.crt";
	my $chainmode  = 0444;

	if(  $reuquire_all  )  {
		export_all($c, $dbh, $basename, $basemode);
	}  elsif(  @{$c->argv}  )  {
		export_cert( $c, $dbh, $pubout, $pubmode, $keyout, $keymode, $chainout, $chainmode, $require_fullchain, @{$c->argv} );
	}  else  {
		print "no export found\n";
	}

	$dbh->disconnect();

	return undef;
} # export

sub info_file($$$) {
	my($c, $dbh, $file) = @_;
	my $text = readfile($file);

	my($certkind, $certid, $cn, $subject, $issuer, $startdate, $enddate, $hash, $inrepo);
	if(  $text =~ m|^-----\s*BEGIN\s+CERTIFICATE\s+REQUEST\s*-----$|m  )  {
		$certkind = "CSR";
		$subject  = openssl_req_subject($text);
		$cn       = get_cn_from_subject($subject);
		$hash     = openssl_req_pubkey($text);
		$inrepo   = $dbh->selectrow_array("SELECT EXISTS (SELECT * FROM sslcsr WHERE hashkey = ?)", {}, $hash);
	}  elsif(  $text =~ m|^-----\s*BEGIN\s+PRIVATE\s+KEY\s*-----$|m  )  {
		$certkind = "KEY";
		$cn       = "(N/A)";
		$hash     = openssl_pkey_pubkey($text);
		$inrepo   = $dbh->selectrow_array("SELECT EXISTS (SELECT * FROM sslkey WHERE hashkey = ?)", {}, $hash);
	}  elsif(  $text =~ m|^-----\s*BEGIN\s+CERTIFICATE\s*-----$|m )  {
		$certkind = "CRT";
		($subject, $issuer)    = openssl_x509_subject($text);
		$cn       = get_cn_from_subject($subject);
		($startdate, $enddate) = openssl_x509_date($text);
		$hash     = openssl_x509_pubkey($text);
		$inrepo   = $dbh->selectrow_array("SELECT EXISTS (SELECT * FROM sslcrt WHERE hashkey = ?)", {}, $hash);
	}  else  {
		$cn       = "(N/A)";
		$certkind = "UNKNOWN";
	}

	if(  defined $hash  )  {
		$certid = $dbh->selectrow_array(q{
			SELECT certid FROM sslcrt WHERE hashkey = ?
			 UNION
			SELECT certid FROM sslcsr WHERE hashkey = ?
			 UNION
			SELECT certid FROM sslkey WHERE hashkey = ?
		}, {}, $hash, $hash, $hash);
	}

	printf "Certificate ID:		%s\n", (defined $certid ? $certid : "N/A");
	printf "CommonName:		%s\n", $cn;
	printf "Active Certificate:	N/A\n";
	printf "Marked Certificate:	N/A\n";
	printf "Stored Certificate:	%s (%s)\n", $certkind, ($inrepo ? "already imported" : "not yet imported");
	printf "Subject:		%s\n", ($subject ne "" ? $subject : "N/A");
	printf "Issuer:			%s\n", ($issuer  ne "" ? $issuer  : "N/A");
	printf "Expiration Date:	%s\n", (defined $startdate && defined $enddate ? "${startdate}Z - ${enddate}Z" : "N/A");
	printf "HPKP type Hash Value:	%s\n", $hash;
	printf "\n";
} # info_file

sub info_repo($$$) {
	my($c, $dbh, $argv) = @_;

	my $where = ($argv =~ /^\d+$/) ? "certid" : "commonname";

	my($certid, $cn, $active, $marked, $subject, $issuer, $startdate, $enddate, $incrt , $incsr, $inkey, $hash) = $dbh->selectrow_array(sprintf(q{
		SELECT certid, commonname, is_active, is_marked, sslcrt.subject, issuer, startdate, enddate, crttext IS NOT NULL, csrtext IS NOT NULL, keytext IS NOT NULL, COALESCE(sslcrt.hashkey, sslcsr.hashkey, sslkey.hashkey)
		  FROM certificate
		  LEFT JOIN sslcrt USING(certid)
		  LEFT JOIN sslcsr USING(certid)
		  LEFT JOIN sslkey USING(certid)
		 WHERE %s = ?
		 ORDER BY CASE WHEN is_active = 't' THEN 0 ELSE 1 END ASC,
		          CASE WHEN is_marked = 't' THEN 0 ELSE 1 END ASC,
			  certid DESC
		 LIMIT 1
	}, $where), {}, $argv);

	if(  !defined $cn  )  {
		printf "No certificate found: %s=%s", $where, $argv;
		next;
	} # NOT REACHABLE #

	printf "Certificate ID:		%d\n", $certid;
	printf "CommonName:		%s\n", $cn;
	printf "Active Certificate:	%s\n", ($active eq "t" ? "YES" : "no");
	printf "Marked Certificate:	%s\n", ($marked eq "t" ? "YES" : "no");
	printf "Stored Certificate:	%s\n", join(" ", ($incrt ? ("CRT") : ()),  ($incsr ? ("CSR") : ()), ($inkey ? ("KEY"): ())) || "!!!BUG!!!";
	printf "Subject:		%s\n", ($subject ne "" ? $subject : "N/A");
	printf "Issuer:			%s\n", ($issuer  ne "" ? $issuer  : "N/A");
	printf "Expiration Date:	%s\n", (defined $startdate && defined $enddate ? "$startdate - $enddate" : "N/A");
	printf "HPKP type Hash Value:	%s\n", $hash;
	printf "\n";
} # info_repo

sub info {
	my $c    = shift;
	my $dbh  = $c->stash->{DBH};

	init($c)  if(  $c->stash->{DBVER} == 0  );

	foreach  my $argv  ( @{$c->argv} )  {
		if(  -r $argv  )  {
			info_file($c, $dbh, $argv);
		}  else  {
			info_repo($c, $dbh, $argv);
		}
	}

	return undef;
} # info
