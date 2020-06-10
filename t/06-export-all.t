use v6;

use Test;
use UNIX::Privileges :ALL;

for UNIX::Privileges::EXPORT::ALL::.keys -> $sym {
    ok(  UNIX::Privileges::EXPORT::ALL::{$sym}, "Symbol $sym imported" );
}
