set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
echo ===CRASH===\n
info registers x1 x19 x20 x21 x22 pc
x/4i $pc
x/32gx 253965063589888
x/32gx 253965063589888+0x400
bt 8
detach
quit
