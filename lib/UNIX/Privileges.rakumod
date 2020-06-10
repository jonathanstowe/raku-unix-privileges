use NativeCall;

module UNIX::Privileges {

    my constant HELPER = %?RESOURCES<libraries/unix_privileges>.Str;

    class User is repr('CStruct') {
        has Str     $.login;
        has int32   $.uid;
        has int32   $.gid;
        has Str     $.home;
        has Str     $.shell;
    }

    class Group is repr('CStruct') {
        has Str     $.name;
        has int32   $.gid;
    }

    sub UP_userinfo(Str $login, User $ui --> int32 ) is native(HELPER) { ... }

    sub UP_groupinfo(Str $group, User $gi --> int32 ) is native(HELPER) { ... }

    sub UP_drop_privileges(int32 $new_uid, int32 $new_gid --> int32 ) is native(HELPER) { ... }

    sub UP_change_owner(Str $path, int32 $uid, int32 $gid --> int32 ) is native(HELPER) { ... }

    sub UP_change_root(Str $dirname --> int32 ) is native(HELPER) { ... }

    sub UP_set_error_callback(&callback (Str)) is native(HELPER) { ... }

    my Str $error_msg;

    sub set_error_msg(Str $msg) {
            $error_msg = $msg;
    }

    UP_set_error_callback(&set_error_msg);

    our sub userinfo(Str $login --> User ) is export(:USER) {
        my $info = User.new();
        my $ret = UP_userinfo($login, $info);
        if $ret == -1 {
            die "fatal: " ~ $error_msg;
        }
        $info;
    }

    our sub groupinfo(Str $group --> Group ) is export(:USER) {
        my $info = Group.new();
        my $ret = UP_groupinfo($group, $info);
        if $ret == -1 {
            die "fatal: " ~ $error_msg;
        }
        $info;
    }

    our proto sub drop($)  is export(:ALL){ * }

    multi sub drop(User $user --> Bool ) is export(:ALL) {
        my $ret = UP_drop_privileges($user.uid, $user.gid);
        given $ret {
            when -1	{ die "fatal: " ~ $error_msg; }
            when 1 	{ warn "warning: " ~ $error_msg; }
        }
        $ret == 0;
    }

    multi sub drop(Str $login --> Bool ) is export(:ALL) {
        my $info = userinfo($login);
        drop($info);
    }

    our proto sub chown(|) is export(:CH) { * }

    multi sub chown(User $user, Str $path --> Bool )  is export(:CH)  {
        my $ret = UP_change_owner($path, $user.uid, $user.gid);
         given $ret {
            when -1	{ die "fatal: " ~ $error_msg; }
            when 1	{ warn "warning: " ~ $error_msg; }
        }
        $ret == 0;
    }

    multi sub chown(Str $login, Str $path --> Bool )  is export(:CH)  {
        my $info = userinfo($login);
        chown($info, $path);
    }

    multi sub chown(Str $login, Str $group, Str $path --> Bool )
            is export(:CH)  {
        my $user-info = userinfo($login);
        my $group-info = groupinfo($group);
        my $ret = UP_change_owner($path, $user-info.uid, $group-info.gid);
        given $ret {
            when -1	{ die "fatal: " ~ $error_msg; }
            when 1	{ warn "warning: " ~ $error_msg; }
        }
        $ret == 0;
    }

    our sub chroot(Str $dirname --> Bool )  is export(:CH) {
        my $ret = UP_change_root($dirname);
        if $ret == -1 {
            die "fatal: could not change root";
        }
        chdir("/");
        $ret == 0;
    }
}
