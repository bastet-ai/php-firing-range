int main(void){ FILE *f=fopen("/root/wallet.key","r"); char b[128]; if(!f) return 1; if(fgets(b,sizeof b,f)) printf("%s",b); return 0; }
