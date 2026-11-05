const fs=require('fs'),path=require('path'),vm=require('vm');const dir=process.argv[2];
global.window=global; global.btoa=(s)=>Buffer.from(s,'binary').toString('base64');
for(const f of ['js/bytes.js',...fs.readdirSync(dir+'/js/protocols').map(x=>'js/protocols/'+x)]) vm.runInThisContext(fs.readFileSync(path.join(dir,f),'utf8'));
const out=[];for(const p of PV.protocols)for(const s of p.steps)for(const e of s.events)if(e.packet){
 const L=e.packet.layers; const w=L.filter(l=>!l.decoded).flatMap(l=>l.fields.flatMap(f=>f.bytes)); const d=L.filter(l=>l.decoded).flatMap(l=>l.fields.flatMap(f=>f.bytes));
 out.push({p:p.id,l:e.label,eth:L[0].name==='Ethernet',w:Buffer.from(w).toString('hex'),d:Buffer.from(d).toString('hex'),names:L.map(l=>l.name)});}
process.stdout.write(JSON.stringify(out));
