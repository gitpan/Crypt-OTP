package Crypt::OTP;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;

@ISA = qw(Exporter AutoLoader);

$VERSION = '1.03';
@EXPORT  = qw(OTP);

sub OTP {
    my $pad_text = "";
    my ( $pad, $message, $mode ) = @_;
    if ($mode) {
        $pad_text = $pad;
    } else {
        local $/ = undef;
        open( PAD, $pad ) || return $!;
        $pad_text = <PAD>;
        close(PAD);
    }

    while ( length($pad_text) < length($message) ) {
        $pad_text .= $pad_text;
    }
    my @message = split ( //, $message );
    my @pad     = split ( //, $pad_text );
    my $cipher  = ();
    my $i;

    for ( $i = 0 ; $i <= $#message ; $i++ ) {
        $cipher .= pack( 'C', unpack( 'C', $message[$i] ) ^ unpack( 'C', $pad[$i] ) );
    }
    return $cipher;
}

1;

__END__

=head1 NAME

Crypt::OTP - Perl implementation of the One Time Pad (hence, OTP) encryption method.

=head1 SYNOPSIS

  use Crypt::OTP;
  $cipher = Crypt::OTP( $pad, $message );
	or
  $cipher = Crypt::OTP( $pad, $message, $mode );

=head1 DESCRIPTION

The One Time Pad encryption method is very simple, and impossible to crack without the actual pad file against which the to-be-encrypted message is XOR'ed.  Encryption and decryption are performed using excactly the same method, and the message will decrypt correctly only if the same pad is used in decryption as was use in encryption.

The safest method of use is to use a large, semi-random text file as the pad, like so:

$ciphertext = OTP( "my_pad.txt", $message );

However, I've also implemented a second method which does not rely on an external pad file, though this mathod is substantially less secure.

$less_secure = OTP( "This text takes the place of my pad file", $message, 1 );

In this example, the "1" instructs the OTP sub-routine to use the contents of the first element as the pad, rather than the default method which is to use the first element as the name of the external pad file.

If the file specified using the first method does not exist, OTP returns zero.  In all other cases, OTP returns the XOR'ed message.

=head1 AUTHOR

Kurt Kincaid, sifukurt@yahoo.com

=head1 SEE ALSO

perl(1).

=cut
