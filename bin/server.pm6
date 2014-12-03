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

$serv.register(sub ($q, $s, $n) {
  await $q.promise;
  try {
    $q.data = from-json($q.data) or die 'dead';
    $n(True);
    CATCH {
      default {
        $s.close('{ "failure": 1, "reason": "Invalid JSON received" }'); 
        $n(False);
      }
    }
  }
});

sub reduce(@selpackages) {
  my @packages;
  for @selpackages.map({(%($_)<name> // '') ~ "\t" ~ (%($_)<owner> // '')}).uniq -> $u {
    my ($name, $owner) = $u.split("\t", 2);
    my $ref;
    for @selpackages -> $p {
      next if (%($p)<owner> // '') ne $owner || (%($p)<name> // '') ne $name;
      $ref = $p if Any ~~ $ref || %($p)<submitted> gt %($ref)<submitted>; 
    }
    @packages.push($ref);
  }
  return @packages;
}

$rest.all(
  / ^ '/login' '/'? $ / => sub ($q, $s, $n) {
    $s.headers<Content-Type> = 'application/json';
    if $q.data.exists_key('username') && $q.data.exists_key('password') {
      $q.data<password> = sha256($q.data<password> ~ 'salt');
      my $query = $orm.search('users', { username => $q.data<username>, password => $q.data<password> });
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
  / ^ '/register' '/'? $ / => sub ($q, $s, $n) {
    if $q.data.exists_key('username') && $q.data.exists_key('password') {
      $q.data<password> = sha256($q.data<password> ~ 'salt');
      my $query = $orm.search('users', { username => $q.data<username>, password => $q.data<password> });
      my $user  = $query.first;
      if Any !~~ $user {
        $s.close("\{ \"failure\": 1, \"reason\": \"username already used\" \}");
      } else {
        my $newuser = $orm.create('users');
        my $ticket  = ('A'..'Z', 0..9).pick(64).join;
        $newuser.set({
          username => 'ZEF:' ~ $q.data<username>,
          password => $q.data<password>,
          uq       => $ticket,
        });
        $newuser.save;
        $s.close("\{ \"success\": 1, \"newkey\": \"$ticket\" \}");
      }
    } else {
      $s.close('{ "failure": 1, "reason": "supply a username/password" }');
    }
  },
  / ^ '/testresult' '/'? $ / => sub ($q, $s, $n) {
    if any qw<package results os perlversion moduleversion>.map({ 
             $q.data.exists_key($_) ?? False !! True 
           }) {
      $s.close('{"error":"supply all required fields"}');
    } else {
      my $user = $orm.search('users', { uq => $q.data<tester> }).first.id // $q.data<tester> // '*';
      my $vers = $orm.search('packages', { name => $q.data<package>, commit => $q.data<moduleversion> }).first;
      if Any ~~ $vers {
        $s.close('{ "failure": 1, "reason": "Module commit ID is required to lookup module version" }');
      } else {
        my $data = {
          package     => $q.data<package>,
          version     => $vers.get('version'),
          user        => $user,
          results     => $q.data<results>,
          os          => $q.data<os>,
          perlversion => $q.data<perlversion>,          
        };
        my $result = $orm.create('tests');
        $result.set($q.data);
        $result.save;
        $s.close('{ "success": 1 }');
      }
    }
  },
  / ^ '/push' '/'? $ / => sub ($q, $s, $n) {
    if any qw<key meta>.map({ $q.data.exists_key($_) ?? False !! True }) || 
       any qw<repository version name>.map({ $q.data<meta>.exists_key($_) ?? False !! True }) {
      $s.close('{ "failure": 1, "reason": "supply all required fields" }');
      return;
    }
    my $authorid = $orm.search('users', { uq => $q.data<key> }).first.id // Any;
    my $vfound   = $orm.search('packages', { owner => $authorid, name => $q.data<meta><name>, version => $q.data<meta><version> }).first // Any;
    if Any ~~ $authorid.WHAT {
      $s.close('{ "failure": 1, "reason": "provide author\'s token" }');
      return;
    }
    if Any !~~ $vfound.WHAT {
      $s.close('{ "failure": 1, "reason": "increment or provide version number and resubmit" }');
      return;
    }
    my $cmd  = "git ls-remote '{$q.data<meta><repository>.subst('\'','\'"\'"\'')}' |grep HEAD |awk '\{print \$1\}'";
    $cmd.say;
    my $data = {
      name  => $q.data<meta><name>,
      owner => $authorid,
      dependencies => $q.data<meta><dependencies> // '{}',
      version      => $q.data<meta><version>,
      repository   => $q.data<meta><repository>,
      submitted    => time,
      commit       => qqx/$cmd/,
    };
    my $pkg = $orm.create('packages');
    $pkg.set($data);
    $pkg.save;
    $s.close('{ "success": 1 }');
  },
  / ^ '/search' '/'? $ / => sub ($q, $s, $n) {
    $s.close('{ "failure": 1, "reason": "what are you looking for" }'), return unless $q.data.exists_key('query'); 
    my @owners   = @($orm.search('users', { username => $q.data<query> }).all).map({ .id; });
    my @packages = reduce(@($orm.search('packages', { '-or' => [ owner => [@owners], name => $q.data<query> ] }).all).map({
      [ 
        name      => .get('name'),
        owner     => .get('owner'),
        version   => .get('version'),
        submitted => .get('submitted'),
      ];
    }));
    my $closer = '[';
    $closer ~= @packages.map({ 
      '{' ~ %($_).map({ "\"{.key.subst('"', '\"')}\":\"{.value.subst('"', '\"')}\"," }).subst(/','$/,'') ~ '},'
    });
    $closer = $closer.subst(/','$/,'') ~ ']';
    $s.close($closer);
  },
  / ^ '/download' '/'? $ / => sub ($q, $s, $n) {
    $s.close('{ "failure":1, "reason": "what download you want" }'), return unless $q.data.exists_key('name');
    my %search       = name => $q.data<name>;
    my $author       = $orm.search('users', { username => $q.data<author> }).first.id // $q.data<author>;
    %search<owner>   = $author          if $q.data<author>  // False;
    %search<version> = $q.data<version> if $q.data<version> // False;
    my @packages = reduce(@($orm.search('packages', %search).all).map({
      [
        repo    => .get('repository'),
        commit  => .get('commit'),
        version => .get('version'),
        owner   => $q.data<author>,
        submitted => .get('submitted'),
      ]
    }));
    $s.close(@packages.perl);
  },
);

$rest.hook($serv);
$serv.register(sub ($q,$s,$n){ 
  $s.status = 404; 
  $s.close('{ "failure": 1, "reason": "endpoint not found idiot" }'); 
});

$serv.listen;
$serv.block;
