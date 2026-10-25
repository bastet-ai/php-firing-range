set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
printf "===CRASH===\n"
info registers x0 x1 x2 x3 x4 x5 x8 x9 x16 x17 x19 x20 x21 x22 pc sp
x/4i $pc
x/16gx $x22-0x20
x/16gx $x20
x/16gx $x21
python
import gdb
base = None
for l in gdb.execute('info proc mappings', to_string=True).splitlines():
    if '/usr/local/bin/php' in l and 'r-xp' in l:
        base = int(l.split()[0], 16); break
if base:
    print('PHPBASE 0x%x' % base)
    print('BG(unserialize) region:')
    gdb.execute('x/8gx 0x%x' % (base + 0x12d99f0 - 0x20))
end
bt 20
detach
quit
