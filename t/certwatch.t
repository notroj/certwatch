#    Copyright 2005-2026 Red Hat, Inc.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#  
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#  
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#   
#    In addition, as a special exception, Red Hat, Inc. gives permission
#    to link the code of this program with the OpenSSL library (or with
#    modified versions of OpenSSL that use the same license as OpenSSL),
#    and distribute linked combinations including the two. You must obey
#    the GNU General Public License in all respects for all of the code
#    used other than OpenSSL. If you modify this file, you may extend
#    this exception to your version of the file, but you are not
#    obligated to do so. If you do not wish to do so, delete this
#    exception statement from your version.

use Test;
use Test::Output qw(stderr_from);
use POSIX qw(strftime);
use Time::Local;
use File::Temp qw(tempdir);

my $certwatch = "../certwatch";

if (! -x $certwatch) {
    plan tests => 1;
    skip("certwatch not present");
    exit 66;
}

$ENV{"TZ"} = "UTC";

my $tmpdir = tempdir(CLEANUP => 1);

plan tests => 44;

sub asntime {
    my ($days) = @_;

    my $time = time() + ($days) * 24 * 60 * 60 + 60;
    return strftime("%y%m%d%H%M%SZ", gmtime($time));
}

sub cmd {
    my ($cmd) = @_;
    
    print "# running $cmd\n";
    system($cmd);
}

# generate a cert into $fn which expires in $days days, with
# a commonName of $host
sub makecert {
    my ($fn, $days, $host, $start) = @_;
    my $expiry = "-not_after ".asntime($days);

    if (defined $start) {
        $expiry .= " -not_before ".asntime($start);
    }

    cmd("openssl req -x509 -subj /C=GB/ST=Berkshire/O=C2Net/CN=$host/ -new -batch " .
        "-key $tmpdir/certwatch.key $expiry -out $tmpdir/$fn");
}

ok cmd("openssl genrsa -out $tmpdir/certwatch.key") == 0;
ok makecert("certw.1d", 1, "www.example.com") == 0;
ok makecert("certw.22d", 22, "www.example.com") == 0;
ok makecert("certw.29d", 29, "www.example.com") == 0;
ok makecert("certw.31d", 30, "www.example.com") == 0;
ok makecert("certw.300d", 300, "www.example.com") == 0;
ok makecert("certw.4000d", 4000, "www.example.com") == 0;
ok makecert("certw.local", 5, "localhost") == 0;
ok makecert("certw.local2", 5, "localhost.localdomain") == 0;
ok makecert("certw.future", 10, "future.example.com", 5) == 0;
ok makecert("certw.past", -5, "expired.example.com", -10) == 0;

my $pfx = "Subject: The certificate for www.example.com";

ok `$certwatch $tmpdir/certw.1d`, "/$pfx will expire tomorrow/";
ok `$certwatch $tmpdir/certw.22d`, "/$pfx will expire in 22 days/";
ok `$certwatch $tmpdir/certw.29d`, "/$pfx will expire in 29 days/";
ok `$certwatch $tmpdir/certw.31d`, '';
ok `$certwatch $tmpdir/certw.300d`, '';
ok `$certwatch $tmpdir/certw.4000d`, '';
ok `$certwatch $tmpdir/certw.local`, '';
ok `$certwatch $tmpdir/certw.local2`, '';

ok `$certwatch $tmpdir/certw.past`, "/expired.example.com has expired/";
ok `$certwatch $tmpdir/certw.future`, 
    "/Subject: The certificate for future.example.com is not yet valid/";
ok `$certwatch nocname.pem`, '';

# Non-zero exit code for certs for which *no* warning should be issued
foreach $c ("31d", "300d", "4000d", "local", "local2") {
    print "# testing certw.$c\n";
    ok system("$certwatch -q $tmpdir/certw.$c") != 0;
}

# Zero exit code for certs for which a warning will be issued
foreach $c ("certw.1d", "certw.22d", "certw.29d", "certw.future", "certw.past") {
    ok system("$certwatch -q $tmpdir/$c"), 0;
}

# non-zero exit for bogus files
ok `$certwatch /etc/passwd`, '';
ok $? >> 8, 1;

# mail validity checking
my $text = `$certwatch $tmpdir/certw.1d`;

ok $text, qr/^To: root\n/m;
ok $text, qr/Subject: /;

my $help = `$certwatch --help`;

ok $?, 0;
ok $help, qr/--address/;
ok $help, qr/--quiet/;
ok $help, qr/--period/;
ok $help, qr/--help/;

my $errout = stderr_from(sub { `$certwatch --what`; });
ok $errout, qr/unrecognized option '--what'/;

# no arguments should print usage to stderr and exit non-zero
my $noargs = stderr_from(sub { system("$certwatch") });
ok $? >> 8, 2;
ok $noargs, qr/Usage:/;
