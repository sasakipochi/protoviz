import json,sys,struct,base64
def csum(b):
    if len(b)%2: b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while s>>16: s=(s&0xffff)+(s>>16)
    return s
def der_walk(b,depth=0):
    i=0
    while i<len(b):
        tag=b[i]; l=b[i+1]; j=i+2
        if l&0x80:
            n=l&0x7f; l=int.from_bytes(b[j:j+n],'big'); j+=n
        if j+l>len(b): raise ValueError('DER overflow')
        if tag&0x20 or tag==0x04 and b[j:j+1] in (b'\x30',b'\x60',b'\x6e'):
            try: der_walk(b[j:j+l],depth+1)
            except ValueError:
                if not tag&0x20: pass
                else: raise
        i=j+l
    return True
bad=0
packets=json.load(open(sys.argv[1]))
for p in packets:
    w=bytes.fromhex(p['w']); o=14 if p['eth'] else 0; msg=[]
    v=w[o]>>4
    if v==4:
        ihl=(w[o]&15)*4; ip=w[o:o+ihl]
        if csum(ip)!=0xffff: msg.append('ipcsum')
        if struct.unpack('!H',w[o+2:o+4])[0]!=len(w)-o: msg.append('iplen')
        proto=w[o+9]; src,dst=w[o+12:o+16],w[o+16:o+20]; up=w[o+ihl:]
        ph=src+dst+bytes([0,proto])+struct.pack('!H',len(up))
    else:
        proto=w[o+6]; src,dst=w[o+8:o+24],w[o+24:o+40]; up=w[o+40:]
        if struct.unpack('!H',w[o+4:o+6])[0]!=len(up): msg.append('ip6len')
        ph=src+dst+struct.pack('!I',len(up))+bytes([0,0,0,proto])
    if proto in (6,17,58):
        if csum(ph+up)!=0xffff: msg.append('l4csum')
    if proto==1 and csum(up)!=0xffff: msg.append('icmpcsum')
    if proto==17 and struct.unpack('!H',up[4:6])[0]!=len(up): msg.append('udplen')
    pay = up[8:] if proto==17 else up[20:] if proto==6 else up
    if p['p']=='kerberos':
        try:
            if proto==17: der_walk(pay)
            else:
                hdr=pay.split(b'\r\n')
                tok=[x for x in hdr if b'Negotiate' in x][0].split(b' ')[-1]
                t=base64.b64decode(tok); der_walk(t); 
                assert t[0]==0x60
        except Exception as e: msg.append('der:'+str(e))
        if p['d']: pass
    if p['p']=='bgp' and proto==6 and len(pay)>0:
        if struct.unpack('!H',pay[16:18])[0]!=len(pay): msg.append('bgplen')
        if pay[18]==1 and pay[28]!=len(pay)-29: msg.append('optlen')
        if pay[18]==2:
            wl=struct.unpack('!H',pay[19:21])[0]; al=struct.unpack('!H',pay[21+wl:23+wl])[0]
            nl=len(pay)-23-wl-al
            if nl<0: msg.append('upd')
    if p['p']=='ipsec' and proto==17:
        ike=pay
        if struct.unpack('!I',ike[24:28])[0]!=len(ike): msg.append('ikelen')
        # ペイロードの連鎖をたどる
        nxt=ike[16]; i=28
        while nxt and i<len(ike):
            pl=struct.unpack('!H',ike[i+2:i+4])[0]; nxt=ike[i]; i+=pl
        if i!=len(ike): msg.append(f'ikechain {i} {len(ike)}')
    if msg: print("NG", p["p"], p["l"], msg)
    bad+=bool(msg)

print(f"{len(packets)} パケットを検証: NG {bad} 件")
sys.exit(1 if bad else 0)
