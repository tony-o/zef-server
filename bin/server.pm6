#!/usr/bin/env perl6

use HTTP::Server::Async;
use HTTP::Server::Async::Plugins::Router::Simple;
use DB::ORM::Quicky;
use JSON::Tiny;

my $host = '0.0.0.0';
my $port = 8080;
my $rest = HTTP::Server::Async::Plugins::Router::Simple.new;
my $serv = HTTP::Server::Async.new(:$host, :$port);
my $orm  = DB::ORM::Quicky.new;

sub sha256($password is rw) {
  return $password;
}

$orm.connect(
  driver  => 'SQLite',
  options => %(
    database => './zef.sqlite3',
  ),
);

$rest.all(
  / ^ '/login' [ '/' ]? $ / => sub ($q, $s, $n) {
    await $q.promise;
    my $data = from-json($q.data);
    $s.headers<Content-Type> = 'application/json';
    if $data.exists_key('username') && $data.exists_key('password') {
      $data<password> = sha256($data<password> ~ 'salt');
      my $query = $orm.search('users', { username => $data<username>, password => $data<password> });
      my $user  = $query.first;
      if Any !~~ $user {
        my $ticket = ('A'..'Z', 0..9).pick(64).join; 
        $user.set({ uq => $ticket });
        $user.save;
        $s.close("\{ \"success\": 1, \"newkey\": \"$ticket\" \}");
      } else {
        $s.close('{ "failure": 1, "reason": "couldn\'t find username/password combo" }');
      }
    } else {
      $s.close('{ "failure": 1, "reason": "supply a username/password" }');
    }
    $n(False);
  },
  / ^ '/register' [ '/' ]? $ / => sub ($q, $s, $n) {
    await $q.promise;
    my $data = from-json($q.data);
    if $data.exists_key('username') && $data.exists_key('password') {
      $data<password> = sha256($data<password> ~ 'salt');
      my $query = $orm.search('users', { username => $data<username>, password => $data<password> });
      my $user  = $query.first;
      if Any !~~ $user {
        $s.close("\{ \"failure\": 1, \"reason\": \"username already used\" \}");
      } else {
        my $newuser = $orm.create('users');
        my $ticket  = ('A'..'Z', 0..9).pick(64).join;
        $newuser.set({
          username => $data<username>,
          password => $data<password>,
          uq       => $ticket,
        });
        $newuser.save;
        $s.close("\{ \"success\": 1, \"newkey\": \"$ticket\" \}");
      }
    } else {
      $s.close('{ "failure": 1, "reason": "supply a username/password" }');
    }
    $n(False);
  },
  / ^ '/testresult' [ '/' ]? $ / => sub ($q, $s, $n) {
    await $q.promise;
    my $data = from-json($q.data);
    if any qw<package results os perlversion moduleversion>.map({ 
             $data.exists_key($_) ?? False !! True 
           }) {
      $s.close('{"error":"supply all required fields"}');
      return; 
    } else {
      my $user = $orm.search('users', { uq => $data<tester> }).first.id // '*';
      
      $s.close($user);
    }
    $n(False);

  },
);

$rest.hook($serv);

$serv.listen;
$serv.block;
