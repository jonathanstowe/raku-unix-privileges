use v6;

use NativeCall;

my constant HELPER = %?RESOURCES<libraries/unix_privileges>.Str;

class UNIX::Privileges::User is repr('CStruct') {
    has Str 	$.login;
    has int32 	$.uid;
    has int32 	$.gid;
    has Str 	$.home;
    has Str 	$.shell;
}

sub UP_userinfo(Str $login, UNIX::Privileges::User $ui --> int32 ) is native(HELPER) { ... }

sub UP_drop_privileges(int32 $new_uid, int32 $new_gid --> int32 ) is native(HELPER) { ... }

sub UP_change_owner(Str $path, int32 $uid, int32 $gid --> int32 ) is native(HELPER) { ... }

sub UP_change_root(Str $dirname --> int32 ) is native(HELPER) { ... }

sub UP_set_error_callback(&callback (Str)) is native(HELPER) { ... }

my Str $error_msg;

sub set_error_msg(Str $msg) {
    $error_msg = $msg;
}

UP_set_error_callback(&set_error_msg);

module UNIX::Privileges {

    our sub userinfo(Str $login --> UNIX::Privileges::User ) {
    	my $info = UNIX::Privileges::User.new();
    	my $ret = UP_userinfo($login, $info);
    	if $ret == -1 {
    		die "fatal: " ~ $error_msg;
    	}
    	$info;
    }

    our proto sub drop($) { * }

    multi sub drop(UNIX::Privileges::User $user --> Bool ) {
    	my $ret = UP_drop_privileges($user.uid, $user.gid);
    	given $ret {
    		when -1	{ die "fatal: " ~ $error_msg; }
    		when 1 	{ warn "warning: " ~ $error_msg; }
    	}
    	$ret == 0;
    }

    multi sub drop(Str $login --> Bool ) {
    	my $info = UNIX::Privileges::userinfo($login);
    	UNIX::Privileges::drop($info);
    }

    our proto sub chown($, $) { * }

    multi sub chown(UNIX::Privileges::User $user, Str $path --> Bool ) {
    	my $ret = UP_change_owner($path, $user.uid, $user.gid);
    	 given $ret {
    		when -1	{ die "fatal: " ~ $error_msg; }
    		when 1	{ warn "warning: " ~ $error_msg; }
    	}
    	$ret == 0;
    }

    multi sub chown(Str $login, Str $path --> Bool ) {
    	my $info = UNIX::Privileges::userinfo($login);
    	UNIX::Privileges::chown($info, $path);
    }

    our sub chroot(Str $dirname --> Bool ) {
    	my $ret = UP_change_root($dirname);
    	if $ret == -1 {
    		die "fatal: could not change root";
    	}
    	chdir("/");
    	$ret == 0;
    }
}
