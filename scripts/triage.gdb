set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
printf "===CRASH===\n"
info registers x0 x1 x2 x8 x9 x16 x17 x19 x20 x21 x22 pc sp
x/4i $pc
x/16gx $x22-0x20
x/16gx $x20
x/16gx $x21
x/16gx $x19
bt 20
info proc mappings
detach
quit
