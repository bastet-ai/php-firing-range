set pagination off
set confirm off
set auto-solib-add off
python
import gdb
base = None
for l in gdb.execute('info proc mappings', to_string=True).splitlines():
    if '/usr/local/bin/php' in l and 'r-xp' in l:
        base = int(l.split()[0], 16)
        break
if base:
    print('PHPBASE 0x%x' % base)
    print(gdb.execute('x/2gx 0x%x' % (base + 0x12d99f0), to_string=True))
else:
    print('NOBASE')
end
detach
quit
