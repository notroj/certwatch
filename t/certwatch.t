
use Test;
use Test::Output qw(stderr_from);

my $certwatch = "../certwatch";

if (! -x $certwatch) {
    plan tests => 1;
    skip("certwatch not present");
    exit 66;
}

plan tests => 39;

# generate a cert into $fn which expires in $days days, with
# a commonName of $host
sub makecert {
    my ($fn, $days, $host) = @_;

    system("openssl req -x509 -subj /C=GB/ST=Berkshire/O=C2Net/CN=$host/ -new -batch " .
           "-key certwatch.key -days $days -out $fn");
}

my $tmp = "./";

ok makecert("certw.1d", 1, "www.example.com") == 0;
ok makecert("certw.22d", 22, "www.example.com") == 0;
ok makecert("certw.29d", 29, "www.example.com") == 0;
ok makecert("certw.31d", 30, "www.example.com") == 0;
ok makecert("certw.300d", 300, "www.example.com") == 0;
ok makecert("certw.4000d", 4000, "www.example.com") == 0;
ok makecert("certw.local", 5, "localhost") == 0;
ok makecert("certw.local2", 5, "localhost.localdomain") == 0;

my $pfx = "Subject: The certificate for www.example.com";

ok `$certwatch certw.1d`, "/$pfx will expire tomorrow/";
ok `$certwatch certw.22d`, "/$pfx will expire in 22 days/";
ok `$certwatch certw.29d`, "/$pfx will expire in 29 days/";
ok `$certwatch certw.31d`, '';
ok `$certwatch certw.300d`, '';
ok `$certwatch certw.4000d`, '';
ok `$certwatch certw.local`, '';
ok `$certwatch certw.local2`, '';

ok `$certwatch expired.pem`, "/$pfx has expired/";
ok `$certwatch notvalid.pem`, 
    "/Subject: The certificate for another.example.com is not yet valid/";
ok `$certwatch nocname.pem`, '';

# Non-zero exit code for certs for which *no* warning should be issued
foreach $c ("31d", "300d", "4000d", "local", "local2") {
    ok system("$certwatch -q certw.$c") != 0;
}

# Zero exit code for certs for which a warning will be issued
foreach $c ("certw.1d", "certw.22d", "certw.29d", "expired.pem", "notvalid.pem") {
    ok system("$certwatch -q $c"), 0;
}

# non-zero exit for bogus files
ok `$certwatch /etc/passwd`, '';
ok $? >> 8, 1;

# mail validity checking
my $text = `$certwatch certw.1d`;

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

