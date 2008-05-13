package FTN::Utils::OS_features;
our $VERSION = "1.00";

BEGIN
{
    require Exporter;
    @ISA = qw(Exporter);
    @EXPORT = qw($needs_binmode $dir_separator);
    1;
}

use strict;
use warnings;

our($needs_binmode, $dir_separator);

require Config;
my $OS = $Config::Config{'osname'};

if    ($OS =~ /^MSWin/i) { $OS = 'WINDOWS';  }
elsif ($OS =~ /^VMS/i)   { $OS = 'VMS';      }
elsif ($OS =~ /^dos/i)   { $OS = 'DOS';      }
elsif ($OS =~ /^MacOS/i) { $OS = 'MACINTOSH';}
elsif ($OS =~ /^os2/i)   { $OS = 'OS2';      }
elsif ($OS =~ /^epoc/i)  { $OS = 'EPOC';     }
elsif ($OS =~ /^cygwin/i){ $OS = 'CYGWIN';   }
else                     { $OS = 'UNIX';     }

# Some OS logic.  Binary mode enabled on DOS, NT and VMS
$needs_binmode = $OS=~/^(WINDOWS|DOS|OS2|CYGWIN)/;


# The path separator is a slash, backslash or semicolon, depending
# on the paltform.
$dir_separator = {
     UNIX    => '/',  OS2 => '\\', EPOC      => '/', CYGWIN => '/',
     WINDOWS => '\\', DOS => '\\', MACINTOSH => ':', VMS    => '/'
   }->{$OS};


1;


=head1 NAME

FTN::OS_features - an auxiliary module for FTN::Forum and FTN::Pkt

=head1 DESCRIPTION

None available yet.

=head1 CREDITS

Thanks for Lincoln D. Stein, an author of CGI.pm

=head1 COPYRIGHT

Copyright 2008 Dmitry V. Kolvakh

This program is free software. 
You may copy or redistribute it under the same terms as Perl itself.

=head1 AUTHOR

Dmitry V. Kolvakh aka Keu

2:5054/89@FIDOnet

=cut
