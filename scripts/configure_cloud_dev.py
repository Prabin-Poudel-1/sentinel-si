"""Create explicit loopback-only developer configuration; never production secrets."""
import getpass
import os
from pathlib import Path

root=Path(__file__).resolve().parents[1]/'cloud'
config=root/'wrangler.local.toml'
secret=root/'.dev.vars'
if config.exists() or secret.exists():
    raise SystemExit('Local configuration exists; review it manually rather than overwriting')
key=getpass.getpass('Choose a development-only key (32+ characters; enter the same key in the local web login): ')
if not 32<=len(key)<=256 or any(c in key for c in '\r\n"\\'):
    raise SystemExit('Use 32–256 characters without quotes, backslashes or newlines')
fd=os.open(secret,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as output: output.write('DEV_AUTH_KEY="'+key+'"\n')
config.write_text((root/'wrangler.toml').read_text().replace('DEV_MODE = "false"','DEV_MODE = "true"'))
config.chmod(0o600)
print('Created private loopback-only development configuration. No production authentication was configured.')
