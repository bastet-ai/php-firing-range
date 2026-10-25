set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
echo ===CRASH===\n
info registers x1 x4 x19 x20 x21 x22 pc
x/4i $pc
python
import gdb
base = None
for l in gdb.execute('info proc mappings', to_string=True).splitlines():
    if '/usr/local/bin/php' in l and 'r-xp' in l:
        base = int(l.split()[0], 16); break
print('PHPBASE 0x%x' % base)
print('BG: ' + gdb.execute('x/2gx 0x%x' % (base + 0x12d99f0), to_string=True))
end
detach
quit
