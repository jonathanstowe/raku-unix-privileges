use v6;

use Test;

use UNIX::Privileges;

plan 5;

{
    my $user = UNIX::Privileges::userinfo(~$*USER);
    is $user.uid, +$*USER, 'user id matches';

    my $group = UNIX::Privileges::groupinfo(~$*GROUP);
    is $group.gid, +$*GROUP, 'group id matches';

    my $filename = '01-noroot';
    spurt($filename, "'twas brillig and the slithy toves\n");

    ok UNIX::Privileges::chown(~$*USER, $filename), 'chown worked (no-op)';
    ok UNIX::Privileges::chown($user, $filename), 'chown worked (no-op)';
    ok UNIX::Privileges::chown(~$*USER, ~$*GROUP, $filename), 'chown worked
(no-op)';


    unlink($filename);
}

# vim: ft=raku6
