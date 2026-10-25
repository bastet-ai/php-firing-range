set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
echo ===CRASH===\n
info registers x1 x19 x20 x21 x22 pc
x/4i $pc
x/8gx 263411890294784
x/40gx 263411890307072
bt 8
detach
quit
