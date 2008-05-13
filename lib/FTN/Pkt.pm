package FTN::Pkt;

use strict;
use warnings;
require 5.8.0;
our $VERSION = "1.00";
package FTN::Pkt::utils;

require 5.6.0;
use strict;
use warnings;
require Exporter;
use vars qw(@ISA @EXPORT_OK %EXPORT_TAGS);

BEGIN
{
    @ISA = qw(Exporter);
    %EXPORT_TAGS = (utils => [qw(parse_addr datetime trunk trunkzero hextime my_sleep)]);
    Exporter::export_ok_tags('utils');
    1;
}

use POSIX qw(strftime);
use Time::HiRes qw(usleep gettimeofday);

my $PRECISION = 0.1;


#========================================================

sub parse_addr($)
{
    my $addr = shift;
    return (undef, undef, undef, undef) unless $addr;
    $addr .= ".0" unless $addr =~ /\.\d+$/;
    my @result = $addr =~ /(\d)\:(\d+)\/(\d+)\.(\d+)/;
    return @result;
}

#========================================================

sub datetime
{
    my @MON = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
    my @curtime = localtime(time);
    return strftime("%d ", @curtime).$MON[$curtime[4]].strftime(" %y  %H:%M:%S", @curtime);
}

#========================================================

sub trunk($$)
{
    my ($str, $len) = @_;
    if (length($str) > $len && $len > 0){
        $str = substr($str, 0, $len);
    }
    return $str;
}

#========================================================

sub trunkzero($$)
{
    return trunk($_[0], $_[1]) . "\0";
}

#========================================================

sub hextime()
{
    my $msec = int(gettimeofday() / $PRECISION) % 0xffffffff;
    return sprintf("%08x", $msec);
#    return sprintf("%08x", time);
}

#========================================================

sub my_sleep()
{
    usleep($PRECISION*1000000*1.1);
}

#========================================================


package FTN::Msg;

use strict;
use warnings;

import FTN::Pkt::utils qw(:utils);


#========================================================

use fields qw(fromaddr toaddr fromname toname tearline origin subj text area msgid reply
              topkt frompkt pid tid);

#========================================================

# fromaddr, toaddr, fromname, toname, tearline, origin, subj, text
# area, msgid, reply
# cludges

sub new
{
    my FTN::Msg $self = shift;
    $self = fields::new($self) unless ref $self;
    $self->update(@_);
    return $self;
}

#========================================================

sub update
{
    my FTN::Msg $self = shift;
    my %params = @_;
    foreach(keys %params){
        $self->{$_} = $params{$_};
    }
}

#========================================================

sub make_msgid(;$)
{
    my FTN::Msg $self = shift;
    my $msgid = shift;
    unless ($msgid){
        $msgid = hextime();
        my_sleep();
    }
    die "make_msgid: unknown fromaddr" unless $self->{fromaddr};
    return ($self->{msgid} = "$self->{fromaddr} $msgid");
}

#========================================================

sub as_string()
{
    my FTN::Msg $self = shift;
    my $res = "\n";
    foreach(qw (fromname fromaddr toname toaddr frompkt topkt frompkt area msgid reply pid subj)) {
        $res .= "$_ : $self->{$_}\n" if exists $self->{$_} and defined $self->{$_};
    }
    $res .= '-' x 72 . "\n$self->{text}\n".'-' x 72 ."\n"
        if exists $self->{text} and defined $self->{text};
    foreach(qw (tearline origin)) {
        $res .= "$_ : $self->{$_}\n" if exists $self->{$_} and defined $self->{$_};
    }
    return $res;
}

#========================================================

sub packed()
{
    my FTN::Msg $self = shift;
    my ($fromzone, $fromnet, $fromnode, $frompoint) = parse_addr($self->{fromaddr});
    my ($tozone, $tonet, $tonode, $topoint) = parse_addr($self->{toaddr});
    my ($pfromzone, $pfromnet, $pfromnode, $pfrompoint) = parse_addr($self->{frompkt});
    my ($ptozone, $ptonet, $ptonode, $ptopoint) = parse_addr($self->{topkt});
    my $template = "v7a20";
    $self->make_msgid() unless ($self->{msgid});
    my $result = pack $template, 2, $pfromnode, $ptonode, $pfromnet, $ptonet,
                      0, 0, datetime();
    $result .= trunkzero(($self->{toname} ? $self->{toname} : "All"), 35);
    $result .= trunkzero($self->{fromname}, 35);
    $result .= trunkzero(($self->{subj} ? $self->{subj} : ""), 71);
    my $msgtail = "\x0";
    if ($self->{area}){
        $result .= "AREA:".$self->{area}."\xd";
        $msgtail = "SEEN-BY: $pfromnet/$pfromnode\x0d\x01PATH: $pfromnet/$pfromnode\x0d\x00";
# -------------->
    }else{
        $result .= "\x01INTL $tozone:$tonet/$tonode $fromzone:$fromnet/$fromnode\xd";
        $result .= "\x01FMPT $frompoint\xd" if $frompoint != 0;
        $result .= "\x01TOPT $topoint\xd" if $topoint != 0;
    }
    $result .= "\x01REPLY: $self->{reply}\x0d" if $self->{reply};
    $result .= "\x01MSGID: $self->{msgid}\x0d";
    $result .= "\x01CHRS: CP866 2\x0d";
    $result .= "\x01PID: $self->{pid}\x0d" if $self->{pid};
    $result .= sprintf("\x01TID: FTN::Pkt %s\x0d", $FTN::Pkt::VERSION) if $self->{tid};
    my $text = $self->{text};
    $text =~ s/\n/\xd/sg;
    $result .= $text;
    $result .= "\x0d--- ".($self->{tearline} ? $self->{tearline} : "")."\xd";
    my $origin = " * Origin: ";
    my $origtext = ($self->{origin} ? $self->{origin} : "");
    my $origtail = " (".$self->{fromaddr}.")\xd";
    my $origtxln = 79 - length ($origin.$origtail);
    $origtext = trunk($origtext, $origtxln);
    $origin .= $origtext .= $origtail;
    $result .= $origin if ($self->{origin} || $self->{area});
    $result .= $msgtail;
    return $result;
}

#========================================================

package FTN::Pkt;
use strict;
use warnings;

import FTN::Pkt::utils qw(:utils);

use FTN::Utils::OS_features;
use Carp qw(croak);


#========================================================

use fields qw(fromaddr toaddr password inbound _msgs);

#========================================================

# fromaddr, toaddr, password, inbound
# msgs

sub new {

    my FTN::Pkt $self = shift;
    $self = fields::new($self) unless ref $self;
    $self->update(@_);
    $self->{_msgs} = [];
    return $self;
}

#========================================================

sub update
{
    my FTN::Pkt $self = shift;
    my %params = @_;
    if(exists $params{_msgs}){
        croak "FATAL: can't update '_msgs' directly!";
    }
    foreach(keys %params){
        $self->{$_} = $params{$_};
    }
}

#========================================================

sub add_msg($)
{
    my FTN::Pkt $self = shift;
    my $msg = shift;
    push @{$self->{_msgs}}, $msg;
}

#========================================================

sub packed()
{
    my FTN::Pkt $self = shift;
    my ($fromzone, $fromnet, $fromnode, $frompoint) = parse_addr($self->{fromaddr});
    my ($tozone, $tonet, $tonode, $topoint) = parse_addr($self->{toaddr});
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);

    my $template = "v13a8v10V";
    my $result = pack $template, $fromnode, $tonode,
                      $year+1900, $mon, $mday, $hour, $min, $sec, 0, 2,
                      $fromnet, $tonet, 0x7766,
                      $self->{password} ? $self->{password} : "",
                      $fromzone, $tozone, 0, 0x100, 0x7766, 1,
                      $fromzone, $tozone, $frompoint, $topoint, 0;
    foreach my $msg(@{$self->{_msgs}}){
        $msg->update(frompkt => $self->{fromaddr}, topkt => $self->{toaddr});
        $result .= $msg->packed();
    }
    $result .= "\x00\x00";
    return $result;
}


#========================================================

sub write_pkt()
{
    my FTN::Pkt $self = shift;
    my $regexp = "${dir_separator}\$";
    $self->{inbound} .= $dir_separator unless $self->{inbound} =~ /$regexp/;
    my $filename = $self->{inbound}.hextime() .".tmp";
    my $newname = $filename;
    $newname =~ s/tmp$/pkt/;
    my @repl = split //, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    for(my $i = 0; -e $filename; $i++){
        if($i >= scalar @repl){die "can't make unique tmp name";}
        substr($filename, -12, 1) = $repl[$i];
    }
    open(PKT, ">", $filename) or die "can't open $filename : $!";
    binmode PKT if $needs_binmode;
    print PKT $self->packed();
    close PKT;
    for(my $i = 0; -e $newname; $i++){
        if($i >= scalar @repl){die "can't make unique pkt name";}
        substr($newname, -12, 1) = $repl[$i];
    }
    rename $filename, $newname or die "can't rename $filename -> $newname : $!"
}

#========================================================

1;

=head1 NAME

FTN::Pkt - a module to make FTN-style mail packets

=head1 DESCRIPTION

None available yet. Sorry :-( 

Will be written in future.

=head1 REQUIREMENTS

In order to install and use this package you will need Perl version
5.6 or better. 

=head1 COPYRIGHT

Copyright 2008 Dmitry V. Kolvakh

This program is free software. 
You may copy or redistribute it under the same terms as Perl itself.

=head1 AUTHOR

Dmitry V. Kolvakh aka Keu

2:5054/89@FIDOnet

=cut
