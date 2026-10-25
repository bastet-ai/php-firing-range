set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
echo ===CRASH===
info registers x0 x1 x2 x4 x19 x20 x21 x22 pc
x/4i $pc
echo ===D===
x/10gx 0xf5ce34e69000
echo ===DTORPAGE===
x/32gx 0xf5ce34e6c000
detach
quit
