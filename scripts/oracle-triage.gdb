set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
echo ===CRASH===\n
info registers x1 x19 x20 x21 x22 pc
x/4i $pc
x/32gx 247827236556800
x/32gx 247827236556800+0x400
bt 8
detach
quit
