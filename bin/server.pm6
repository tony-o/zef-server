#!/usr/bin/env perl6

use HTTP::Server::Async;
use HTTP::Server::Async::Plugins::Router::Simple;
use DB::ORM::Quicky;
use JSON::Tiny;

my $host = '0.0.0.0';
my $port = 8080;
my $rest = HTTP::Server::Async::Plugins::Router::Simple.new;
my $serv = HTTP::Server::Async.new;
my $orm  = DB::ORM::Quicky.new(:$host, :$port);

$orm.connect(
  driver  => 'sqlite',
  options => %(
    database => 'data.sqlite3',
  ),
);

$rest.all(
  / ^ '/login' [ '/' ]? $ / => sub ($q, $s, $n) {
    $s.close('Dumbass.');    
  },
);

$rest.hook($serv);

$serv.listen;
$serv.block;
