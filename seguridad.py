# Ejecutar SIEMPRE antes de publicar: python3 seguridad.py index.html
# Recalcula la huella (hash) del script y escribe la política de seguridad (CSP) en la página.
import re,hashlib,base64,sys
p=sys.argv[1] if len(sys.argv)>1 else 'index.html'
s=open(p,encoding='utf-8').read()
s=re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>\n?','',s)
s=re.sub(r'<meta name="referrer"[^>]*>\n?','',s)
scripts=re.findall(r'<script>(.*?)</script>',s,flags=re.S)
assert len(scripts)==1,'se esperaba 1 script en linea'
h=base64.b64encode(hashlib.sha256(scripts[0].encode('utf-8')).digest()).decode()
csp=("default-src 'none'; script-src 'sha256-%s'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
     "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' data: blob: https:; "
     "connect-src https://script.google.com https://script.googleusercontent.com; "
     "base-uri 'none'; form-action 'none'; object-src 'none'; upgrade-insecure-requests")%h
tag='<meta http-equiv="Content-Security-Policy" content="%s">\n<meta name="referrer" content="strict-origin-when-cross-origin">\n'%csp
s=s.replace('<meta name="viewport"',tag+'<meta name="viewport"',1)
open(p,'w',encoding='utf-8').write(s)
print('CSP lista, hash',h)
