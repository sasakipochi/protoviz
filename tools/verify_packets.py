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

def u16(b,i): return struct.unpack('!H',b[i:i+2])[0]
def dns_name(b,i):
    while True:
        l=b[i]
        if l==0: return i+1
        if l&0xc0==0xc0: return i+2
        i+=1+l
def dns_check(b):
    qd,an,ns,ar=struct.unpack('!4H',b[4:12]); i=12
    for _ in range(qd): i=dns_name(b,i)+4
    for _ in range(an+ns+ar):
        i=dns_name(b,i); i+=10+u16(b,i+8)
    return i==len(b)
def opts6(b):  # DHCPv6 オプションの連鎖 (リレーメッセージの中も)
    i=0
    while i<len(b):
        code,l=struct.unpack('!HH',b[i:i+4]); body=b[i+4:i+4+l]
        if len(body)!=l: return False
        if code==9 and not dhcp6(body): return False
        if code==3 and not opts6(body[12:]): return False
        i+=4+l
    return i==len(b)
def dhcp6(b): return opts6(b[34:]) if b[0] in (12,13) else opts6(b[4:])
def hs_walk(b):
    i=0
    while i<len(b): i+=4+int.from_bytes(b[i+1:i+4],'big')
    return i==len(b)
def tls_check(b):
    i=0; recs=[]
    while i<len(b):
        t=b[i]; l=u16(b,i+3); recs.append((t,b[i+5:i+5+l])); i+=5+l
    if i!=len(b): return None
    for t,r in recs:
        if t==22:
            if not hs_walk(r): return None
            if r[0] in (1,2):
                j=4+2+32; j+=1+r[j]
                j+=2 if r[0]==2 else 2+u16(r,j)
                j+=1 if r[0]==2 else 1+r[j]
                end=j+2+u16(r,j); j+=2
                while j<end: j+=4+u16(r,j+2)
                if j!=end or end!=len(r): return None
    return recs
def h2_walk(b):
    if b.startswith(b'PRI * HTTP/2.0'): b=b[24:]
    i=0
    while i<len(b): i+=9+int.from_bytes(b[i:i+3],'big')
    return i==len(b)
bad=0
packets=json.load(open(sys.argv[1]))
for p in packets:
    w=bytes.fromhex(p['w']); o=14 if p['eth'] else 0; msg=[]
    dl=[(n,bytes.fromhex(x)) for n,x in p['dl']]
    if p['eth'] and u16(w,12) in (0x0806,0x8035):
        a=w[14:]
        if a[:6]!=bytes([0,1,8,0,6,4]): msg.append('arphdr')
        if len(w)<60: msg.append('short')
        if (u16(w,12)==0x0806)!=(u16(a,6) in (1,2)): msg.append('arpop')
        if msg: print("NG", p["p"], p["l"], msg)
        bad+=bool(msg); continue
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
    if proto==17:
        sp,dp=u16(up,0),u16(up,2); d=up[8:]
        if 53 in (sp,dp) and not dns_check(d): msg.append('dns')
        if 123 in (sp,dp) and len(d)!=48: msg.append('ntplen')
        if {sp,dp}&{67,68}:
            if len(d)<300 or d[236:240]!=bytes.fromhex('63825363'): msg.append('dhcphdr')
            i=240
            while i<len(d) and d[i]!=255: i+=2+d[i+1] if d[i] else 1
            if i>=len(d) or any(d[i+1:]): msg.append('dhcpopts')
        if {sp,dp}&{546,547} and not dhcp6(d): msg.append('dhcp6opts')
    if proto==58 and up[0] in (133,134,135,136):
        i={133:8,134:16,135:24,136:24}[up[0]]
        while i+1<len(up):
            if up[i+1]==0: break
            i+=8*up[i+1]
        if i!=len(up): msg.append('ndopts')
    if proto==6 and 443 in (u16(up,0),u16(up,2)) and len(up)>20:
        recs=tls_check(up[20:])
        if recs is None: msg.append('tls')
        else:
            names=[n for n,_ in dl]
            h2=b''.join(x for n,x in dl[next((k for k,n in enumerate(names) if n.startswith('HTTP/2')),len(dl)):])
            if h2:
                if not h2_walk(h2): msg.append('h2')
                if recs[-1][0]!=23 or len(recs[-1][1])!=len(h2)+17: msg.append('h2rec')
                if not dns_check(dl[-1][1]): msg.append('dohdns')
            hs=[x for n,x in dl if '暗号の中身' in n or 'Finished' in n]
            for x in hs:
                if not hs_walk(x): msg.append('enchs')
                if not any(t==23 and len(r)==len(x)+17 for t,r in recs): msg.append('enclen')
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
