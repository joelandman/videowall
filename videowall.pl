#!/opt/scalable/bin/perl 

use lib "lib/"; 
use strict;
use v5.14;
use Mojolicious::Lite;
use POSIX;
use File::Spec;

use constant cnc_version    => 0.10;
use constant cnc_label      => "Labrador";

use Config::JSON;
use Data::Dumper;
use URI;
use Crypt::PRNG qw(random_bytes random_bytes_hex random_bytes_b64 random_bytes_b64u
                      random_string random_string_from rand irand);
#use JSON -support_by_pp;
use JSON::PP;
 

my ($server,$debug,$verbose);


# generate a cryptographical PRNG based cookie
&set_secure_cookie();

my $comp_root   = POSIX::getcwd;
plugin 'Mason1Renderer' => 
    { 
        interp_params  =>  { 
                             comp_root => File::Spec->catfile($comp_root,"root"),                              
                             static_source_touch_file=>"$comp_root/clear",
			                       ignore_warnings_expr => '.',
                           },
        request_params =>  { error_format => "brief"  }
    };

helper whois => sub {
    my $self  = shift;
    my $agent = $self->req->headers->user_agent || 'Anonymous';
    my $ip    = $self->tx->remote_address;
    my $lip	  = $self->tx->local_address;
    my $secure= $self->req->is_secure;
    my $ret   = { agent => $agent, ip => $ip, local_address => $lip, secure => $secure };
    return $ret;
  };

helper get_any_arg_types_into_hash => sub  {
  my $self              = shift;
  my $json_arg_string   = $self->req->body;
  my @params            = $self->param;
        
 
  my $content;
 
  # copy parameters into content hash
  if (@params) {
    foreach my $p (@params) {
      $content->{$p} = $self->param($p);
    }  
   }
 # if ((defined($json_arg_string)) && ($json_arg_string ne ""))
 #  {
 #   my $json = Mojo::JSON->decode($json_arg_string);
 #   foreach my $p (keys %{$json}) {
 #     $content->{$p} = $json->{$p};
 #   }
 #  }
  return $content;
};



get '/' => sub {
  my $self = shift;
  $self->render('index.html', handler => "mason" );
};

get '/version'  => sub {
  my $self = shift;
  my $whois     = $self->whois;
  $self->render(text => (sprintf "{ \"version\" : \"%s\"\, \"label\" : \"%s\" }",cnc_version,cnc_label));
};

get '/ping'     => sub {
  my $self = shift;
  my $whois     = $self->whois;
  $self->render(text => (sprintf "{ \"date\" : \"%s\" , \"client\" : \"%s\" }",(scalar localtime),$whois->{ip}));
};

get '/test' => sub {
  my $self = shift;
  my $net   = Scalable::Status->new();
  my $nets  = $net->get_nets();
  $self->render('index.html', handler => "mason",  );
};


### application settings
app->sessions->default_expiration(1); # set expiry to 1 hour

app->start(qw(daemon --listen http://*:6123));

sub set_secure_cookie {
  # generate a secure cookie secret
  my $length  = 32;
  my @ch        = ['0'..'9', 'A'..'Z', 'a'..'z', ,'_', ' '];
  my $pass      = random_string_from(@ch,$length);
  app->secrets($pass);
}

