import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.57.4";

const url = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SB_SERVICE_ROLE_KEY") || "";
const anonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
const resendKey = Deno.env.get("RESEND_API_KEY") || "";
const db = createClient(url, serviceKey, { auth: { persistSession: false } });
const legacyUrl = "https://script.google.com/macros/s/AKfycbz_9Rzy2acFm9sOKGJfvghOSt1TO3SCukRd3XJ5j3-YwdqkovGpwflaln63gAEWu74W/exec";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function out(data: unknown, callback = "") {
  const body = callback ? `${callback}(${JSON.stringify(data)});` : JSON.stringify(data);
  return new Response(body, { headers: { ...cors, "Content-Type": callback ? "application/javascript; charset=utf-8" : "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}
function clean(v: unknown, max = 500) { return String(v ?? "").trim().slice(0, max); }
function id() { return crypto.randomUUID().replaceAll("-", "").slice(0, 12).toUpperCase(); }
async function sha256(v:string){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(v));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("")}
function randomHex(bytes=24){const a=crypto.getRandomValues(new Uint8Array(bytes));return [...a].map(x=>x.toString(16).padStart(2,"0")).join("")}
async function passwordVerifier(clientHash:string,salt:string){return await sha256(`${salt}:${clientHash}`)}
async function saveCredential(szerepkor:string,felhasznalo:string,clientHash:string,soforId:string|null){const salt=randomHex(18),password_verifier=await passwordVerifier(clientHash,salt);await db.from("login_credentials").upsert({szerepkor,felhasznalo,password_verifier,salt,sofor_id:soforId,aktiv:true,frissitve:new Date().toISOString()},{onConflict:"szerepkor,felhasznalo"})}
async function issueSession(szerepkor:string,felhasznalo:string,soforId:string|null){const token=randomHex(32);const {error}=await db.from("login_sessions").insert({token_hash:await sha256(token),szerepkor,felhasznalo,sofor_id:soforId,lejar:new Date(Date.now()+30*24*3600*1000).toISOString()});if(error){console.error("issueSession",error);throw new Error("Munkamenet létrehozási hiba: "+error.message)}return token}
async function legacyLogin(szerepkor:string,felhasznalo:string,clientHash:string){const cb="cb";const q=new URLSearchParams({api:"1",muvelet:szerepkor==="admin"?"adminBelepesHash":"soforBelepesHash",callback:cb,felhasznalo,jelszoHash:clientHash});const r=await fetch(`${legacyUrl}?${q}`);if(!r.ok)return null;const t=await r.text();const m=t.match(/^cb\((.*)\);?\s*$/s);if(!m)return null;try{return JSON.parse(m[1])}catch{return null}}
async function legacyWebCall(name:string,args:any[]){const cb="cb";const q=new URLSearchParams({api:"1",muvelet:"webHivas",callback:cb,nev:name,args:encodeURIComponent(JSON.stringify(args))});const r=await fetch(`${legacyUrl}?${q}`);if(!r.ok)return null;const t=await r.text();const m=t.match(/^cb\((.*)\);?\s*$/s);if(!m)return null;try{return JSON.parse(m[1])}catch{return null}}
function normalizeTrip(x: any, i = 0) {
  return { sor: i + 1, id: x.id, azonosito: x.azonosito, nev: x.nev, telefon: x.telefon, email: x.email, indulas: x.indulas, cel: x.cel,
    datum: x.datum, ido: x.ido?.slice?.(0,5) || x.ido || "", utasok: x.utasok, megjegyzes: x.megjegyzes, statusz: x.statusz,
    sofor: x.sofor_nev || "", menetido: x.menetido_perc || 0, erkezes: x.varhato_erkezes?.slice?.(0,5) || "", letrehozva: x.letrehozva };
}
async function role(token: string, wanted?: string) {
  if (!token) return null;
  const {data:session}=await db.from("login_sessions").select("*").eq("token_hash",await sha256(token)).gt("lejar",new Date().toISOString()).maybeSingle();
  if(session){if(wanted&&session.szerepkor!==wanted)return null;return{szerepkor:session.szerepkor,sofor_id:session.sofor_id,email:session.szerepkor==="ugyfel"?session.felhasznalo:"",user_id:null,user:{id:null,user_metadata:{}}}}
  const { data: ud } = await db.auth.getUser(token);
  if (!ud.user) return null;
  const { data } = await db.from("app_roles").select("*").eq("user_id", ud.user.id).maybeSingle();
  if (!data) {
    if (wanted) return null;
    const email=clean(ud.user.email,240).toLowerCase();
    if(!email)return null;
    const {data:u}=await db.from("ugyfelek").select("id").eq("email",email).maybeSingle();
    return {szerepkor:"ugyfel",ugyfel_id:u?.id||null,email,user_id:ud.user.id,user:ud.user};
  }
  if (wanted && data.szerepkor !== wanted) return null;
  return { ...data, email:data.email||clean(ud.user.email,240).toLowerCase(), user: ud.user };
}
async function tripByRow(row: unknown, active = false) {
  if (typeof row === "string" && /^[0-9a-f-]{32,36}$/i.test(row)) return row;
  if (typeof row === "string" && /^[A-Z0-9]{8,20}$/i.test(row)) { const {data}=await db.from("fuvarok").select("id").eq("azonosito",row).maybeSingle(); if(data?.id)return data.id; }
  const n = Math.max(1, Number(row) || 1);
  let q:any = db.from("fuvarok").select("id");
  if (active) q=q.in("statusz",["Új rendelés","Elvállalva"]);
  const { data } = await q.order("datum").order("ido", { nullsFirst: true }).order("letrehozva").range(n - 1, n - 1).maybeSingle();
  return data?.id || null;
}
async function awardRidePoints(f:any){
 const email=clean(f?.email,240).toLowerCase();if(!email)return;
 const {data:u}=await db.from("ugyfelek").select("id,pont,teljesitett_fuvar,szint").ilike("email",email).maybeSingle();if(!u)return;
 // Ugyanazért a fuvarért csak egyszer járhat pont, a régi és az új naplóelnevezéseket is figyeljük.
 const {data:done}=await db.from("pont_naplo").select("id").eq("fuvar_id",f.id).limit(1);
 if(done?.length)return;
 const n=(Number(u.teljesitett_fuvar)||0)+1;
 let bonus=0,bonusNev="";
 if(n===10){bonus=1000;bonusNev="Ezüst szint bónusz"}
 else if(n===25){bonus=2000;bonusNev="Arany szint bónusz"}
 else if(n===50){bonus=3000;bonusNev="Platina szint bónusz"}
 const ridePoints=100,add=ridePoints+bonus;
 const {error}=await db.from("pont_naplo").insert({ugyfel_id:u.id,pont:add,tipus:"fuvar_jutalom",megjegyzes:n+". teljesített fuvar: +"+ridePoints+" pont"+(bonus?" + "+bonus+" bónuszpont ("+bonusNev+")":""),fuvar_id:f.id});
 if(error){console.error("pont naplo",error);return}
 const szint=n>=50?"Platina":n>=25?"Arany":n>=10?"Ezüst":"Bronz";
 const {error:ue}=await db.from("ugyfelek").update({pont:(Number(u.pont)||0)+add,teljesitett_fuvar:n,szint,frissitve:new Date().toISOString()}).eq("id",u.id);
 if(ue)console.error("ugyfel pont update",ue);
}
async function sendOtp(email: string, redirectTo: string, meta: Record<string,string> = {}) {
  const auth = createClient(url, anonKey, { auth: { persistSession: false } });
  return await auth.auth.signInWithOtp({ email, options: { emailRedirectTo: redirectTo, data: meta, shouldCreateUser: true } });
}

async function sendMail(to:string|string[],subject:string,html:string,kind:string="transactional"){
  if(!resendKey) throw new Error("RESEND_API_KEY hiányzik");
  const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+resendKey},body:JSON.stringify({from:"Autóbérlés sofőrrel <ertesites@autoberlessoforrelkiskoros.hu>",reply_to:"rendeles@autoberlessoforrelkiskoros.hu",to:Array.isArray(to)?to:[to],subject,html,text:html.replace(/<br\s*\/?\s*>/gi,"\n").replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim()})});
  if(!r.ok) throw new Error("Resend: "+await r.text());
  return await r.json();
}
function esc(v:unknown){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]||m))}
function shortAddress(x:any){const a=x?.address||{};const city=a.city||a.town||a.village||a.municipality||a.hamlet||"";const road=a.road||a.pedestrian||a.residential||a.street||a.place||"";const no=a.house_number||"";const parts=[city,[road,no].filter(Boolean).join(" ")].filter(Boolean);return parts.join(", ")||String(x?.display_name||"").split(",").slice(0,3).join(",").trim()}
async function notifyWorkingDrivers(f:any){const {data:drivers}=await db.from("soforok").select("email,nev").eq("aktiv",true).eq("dolgozik",true).not("email","is",null);for(const d of drivers||[]){if(clean(d.email,240).includes("@"))try{await sendMail(d.email,"Új fuvar érkezett",`<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto"><h2>Új fuvar érkezett</h2><p>Új rendelés érkezett a sofőr rendszerbe.</p><p><b>Indulás:</b> ${esc(f.indulas)}<br><b>Cél:</b> ${esc(f.cel)}<br><b>Időpont:</b> ${esc(f.datum)} ${esc(f.ido||"minél hamarabb")}</p><p><a href="https://autoberlessoforrelkiskoros.hu/sofor/panel/" style="display:inline-block;padding:12px 18px;background:#ffc400;color:#111;text-decoration:none;border-radius:8px;font-weight:bold">SOFŐR PANEL MEGNYITÁSA</a></p><p style="font-size:12px;color:#666">Automatikus szolgáltatási értesítés az Autóbérlés sofőrrel rendszerből.</p></div>`)}catch(e){console.error("driver email",d.email,e)}}}
const etaGeoCache=new Map<string,{lat:number,lon:number,at:number}>();
async function geocodeAddress(q:string){
 const cacheKey=String(q||"").trim().toLocaleLowerCase("hu-HU");const cached=etaGeoCache.get(cacheKey);if(cached&&Date.now()-cached.at<6*3600*1000)return cached;
 const raw=String(q||"").trim(),variants=[raw,raw.replace(/,?\s*\d{4}\s+Magyarország\s*$/i,""),raw.replace(/\bu\.\s*/gi,"utca ")];
 const parts=raw.split(",").map((x:string)=>x.trim()).filter(Boolean);
 if(parts.length>1){variants.push(parts.slice(0,2).join(", "));variants.push(parts[0]);variants.push(parts[parts.length-1]+", "+parts[0]);variants.push(parts[0]+", "+parts[parts.length-1]);}
 if(/Kék Duna Vendéglő/i.test(raw))variants.push("Kék Duna Vendéglő Kalocsa","Kalocsa Kék Duna Vendéglő");
 if(/Szerencsecsillag Vendégház/i.test(raw))variants.push("Szerencsecsillag Vendégház Kiskőrös","Középcebe tanya Kiskőrös");
 if(/Auchan/i.test(raw)&&/Kecskemét/i.test(raw))variants.unshift("6000 Kecskemét, Dunaföldvári utca 2");
 for(const v of [...new Set(variants.filter(Boolean))]){try{const r=await fetch("https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=hu&q="+encodeURIComponent(v),{headers:{"User-Agent":"AutoberlesSoforrel/1.0"}});const a=r.ok?await r.json():[];if(a?.[0]){const p={lat:Number(a[0].lat),lon:Number(a[0].lon),at:Date.now()};etaGeoCache.set(cacheKey,p);return p}}catch{}}
 return null
}
async function routeMinutes(a:string,b:string){if(!a||!b)return 0;const [x,y]=await Promise.all([geocodeAddress(a),geocodeAddress(b)]);if(!x||!y)return 0;const r=await fetch(`https://router.project-osrm.org/route/v1/driving/${x.lon},${x.lat};${y.lon},${y.lat}?overview=false`,{headers:{"User-Agent":"AutoberlesSoforrel/1.0"}});const j=r.ok?await r.json():null;return j?.routes?.[0]?.duration?Math.max(1,Math.ceil(Number(j.routes[0].duration)/60)):0}
async function routeCoords(a:any,b:any){if(!a||!b)return 0;try{const r=await fetch(`https://router.project-osrm.org/route/v1/driving/${Number(a.lng??a.lon)},${Number(a.lat)};${Number(b.lng??b.lon)},${Number(b.lat)}?overview=false`,{headers:{"User-Agent":"AutoberlesSoforrel/1.0"}});const j=r.ok?await r.json():null;return j?.routes?.[0]?.duration?Math.max(1,Math.ceil(Number(j.routes[0].duration)/60)):0}catch{return 0}}
async function etaGps(live:any,addr:string){const p=await geocodeAddress(addr);return p?await routeCoords(live,p):0}
async function etaDriver(driver:any,target:any){
 const {data:jobs}=await db.from("fuvarok").select("id,indulas,cel,letrehozva").eq("sofor_id",driver.id).eq("statusz","Elvállalva").order("letrehozva");
 const {data:live}=await db.from("sofor_helyzet").select("lat,lng,frissitve").eq("sofor_id",driver.id).gte("frissitve",new Date(Date.now()-180000).toISOString()).maybeSingle();
 const all=jobs||[],targetIndex=all.findIndex((x:any)=>x.id===target?.id);
 const js=targetIndex>=0?all.slice(0,targetIndex):all;let mins=0,last:string|null=null;
 if(js.length){
   if(live)mins+=await etaGps(live,js[0].indulas);
   mins+=(await routeMinutes(js[0].indulas,js[0].cel))||30;last=js[0].cel;
   for(let i=1;i<js.length;i++){mins+=(await routeMinutes(last!,js[i].indulas))||10;mins+=(await routeMinutes(js[i].indulas,js[i].cel))||30;last=js[i].cel}
   mins+=(await routeMinutes(last!,target.indulas))||10;
 }else if(live)mins+=await etaGps(live,target.indulas);
 else return{mins:null,jobs:0};
 return{mins:Math.max(1,Math.round(mins)),jobs:js.length}
}
let etaRefreshRunning=false;
async function refreshAllEtas(){
 if(etaRefreshRunning)return;etaRefreshRunning=true;
 try{
  const today=new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date());
  const [{data:drivers},{data:trips}]=await Promise.all([
   db.from("soforok").select("id,nev").eq("aktiv",true).eq("dolgozik",true),
   db.from("fuvarok").select("*").eq("datum",today).is("ido",null).in("statusz",["Új rendelés","Elvállalva"]).order("letrehozva")
  ]);
  const ds=drivers||[],rows=trips||[],stamp=new Date().toISOString(),updates:any[]=[];
  for(const f of rows){
   if(f.statusz==="Elvállalva"&&f.sofor_id){
    const d=ds.find((x:any)=>x.id===f.sofor_id);if(!d)continue;
    const e=await etaDriver(d,f);if(e.mins!==null)updates.push({id:f.id,menetido_perc:e.mins,sorban:e.jobs+1,ajanlott_sofor_id:d.id,ajanlott_sofor_nev:d.nev});
   }else if(f.statusz==="Új rendelés"){
    const vals=(await Promise.all(ds.map(async(d:any)=>({d,e:await etaDriver(d,f)})))).filter((x:any)=>x.e.mins!==null).sort((a:any,b:any)=>a.e.mins-b.e.mins);
    if(vals.length){const b=vals[0];updates.push({id:f.id,menetido_perc:b.e.mins,sorban:b.e.jobs+1,ajanlott_sofor_id:b.d.id,ajanlott_sofor_nev:b.d.nev})}
   }
  }
  await Promise.all(updates.map(u=>db.from("fuvarok").update({menetido_perc:u.menetido_perc,sorban:u.sorban,ajanlott_sofor_id:u.ajanlott_sofor_id,ajanlott_sofor_nev:u.ajanlott_sofor_nev,eta_frissitve:stamp}).eq("id",u.id)));
 }catch(e){console.error("ETA_BACKGROUND",e)}finally{etaRefreshRunning=false}
}
function refreshEtaBg(){try{EdgeRuntime.waitUntil(refreshAllEtas())}catch{refreshAllEtas()}}
async function queueInfo(f:any){
 if(!f?.sofor_id||f.statusz!=="Elvállalva")return{pozicio:null,varakozas:null};
 const {data:d}=await db.from("soforok").select("id,nev").eq("id",f.sofor_id).maybeSingle();if(!d)return{pozicio:null,varakozas:null};
 const {data:list}=await db.from("fuvarok").select("id,letrehozva").eq("sofor_id",f.sofor_id).eq("statusz","Elvállalva").order("letrehozva");
 const js=list||[],idx=js.findIndex((x:any)=>x.id===f.id);
 if(idx<=0){const {data:live}=await db.from("sofor_helyzet").select("lat,lng,frissitve").eq("sofor_id",f.sofor_id).gte("frissitve",new Date(Date.now()-180000).toISOString()).maybeSingle();return{pozicio:1,varakozas:live?await etaGps(live,f.indulas):null}}
 const before=await etaDriver(d,f);return{pozicio:idx+1,varakozas:before.mins}
}
async function fleetQueueInfo(f:any){
 if(f?.statusz==="Elvállalva"&&f?.sofor_id)return await queueInfo(f);
 if(f?.statusz!=="Új rendelés")return{pozicio:null,varakozas:null};
 const {data:drivers}=await db.from("soforok").select("id,nev").eq("aktiv",true).eq("dolgozik",true);const ds=drivers||[];
 if(!ds.length)return{pozicio:null,varakozas:null,soforok:0,elotte:null};
 const vals=await Promise.all(ds.map(async(d:any)=>({d,e:await etaDriver(d,f)})));vals.sort((x:any,y:any)=>x.e.mins-y.e.mins);
 const best=vals[0];console.log("ETA_TRACE",{target:String(f.id),pickup:f.indulas,bestDriver:best.d.nev,mins:best.e.mins,jobs:best.e.jobs});return{pozicio:best.e.jobs+1,varakozas:best.e.mins,soforok:ds.length,elotte:best.e.jobs,ajanlottSofor:best.d.nev}
}
async function publicAction(name: string, p: any, origin: string) {
  if(name==="torzsFelhasznaloBelepes"){
    const az=clean(p.args?.[0],240).toLowerCase(),clientHash=clean(p.args?.[1],128).toLowerCase();
    if(!az||!/^[a-f0-9]{64}$/.test(clientHash))return{siker:false,uzenet:"Hibás email/felhasználónév vagy jelszó."};
    const legacy=await legacyWebCall("torzsFelhasznaloBelepes",[az,clientHash]);
    if(!legacy?.siker||!legacy.token)return{siker:false,uzenet:legacy?.uzenet||"Hibás email/felhasználónév vagy jelszó."};
    const profil=await legacyWebCall("torzsProfilLekerdezese",[legacy.token]),u=profil?.profil||{};
    const email=clean(u.email||az,240).toLowerCase();
    const {data:existing}=await db.from("ugyfelek").select("id").eq("email",email).maybeSingle();
    if(existing?.id) await db.from("ugyfelek").update({legacy_id:clean(u.id,160)||null,nev:clean(u.nev,160)||email.split("@")[0],telefon:clean(u.telefon,60),pont:Number(u.pont)||0,teljesitett_fuvar:Number(u.teljesitettFuvar)||0,szint:clean(u.szint,40)||"Bronz",frissitve:new Date().toISOString()}).eq("id",existing.id);
    else await db.from("ugyfelek").insert({legacy_id:clean(u.id,160)||null,nev:clean(u.nev,160)||email.split("@")[0],telefon:clean(u.telefon,60),email,pont:Number(u.pont)||0,teljesitett_fuvar:Number(u.teljesitettFuvar)||0,szint:clean(u.szint,40)||"Bronz",frissitve:new Date().toISOString()});
    const token=await issueSession("ugyfel",email,null);
    return{siker:true,token,profil:{nev:clean(u.nev,160)||email.split("@")[0],telefon:clean(u.telefon,60),email,pont:Number(u.pont)||0,teljesitettFuvar:Number(u.teljesitettFuvar)||0,szint:clean(u.szint,40)||"Bronz"}};
  }
  if(name==="torzsFelhasznaloRegisztracio"||name==="torzsRegisztracioMegerosites"){
    return await legacyWebCall(name,p.args||[])||{siker:false,uzenet:"Kapcsolati hiba."};
  }
  if(name==="adminBelepesHash"||name==="soforBelepesHash"){
    const szerepkor=name==="adminBelepesHash"?"admin":"sofor",felhasznalo=clean(p.felhasznalo,120).toLowerCase(),clientHash=clean(p.jelszoHash,128).toLowerCase();
    if(!felhasznalo||!/^[a-f0-9]{64}$/.test(clientHash))return{siker:false,uzenet:"Hibás felhasználónév vagy jelszó."};
    const {data:c}=await db.from("login_credentials").select("*").eq("szerepkor",szerepkor).eq("felhasznalo",felhasznalo).eq("aktiv",true).maybeSingle();
    let soforId=c?.sofor_id||null,ok=!!c&&await passwordVerifier(clientHash,c.salt)===c.password_verifier,legacy:any=null;
    if(!c){legacy=await legacyLogin(szerepkor,felhasznalo,clientHash);ok=!!legacy?.siker;if(ok&&szerepkor==="sofor"){const{data:s}=await db.from("soforok").select("id,nev").eq("felhasznalo",felhasznalo).eq("aktiv",true).maybeSingle();soforId=s?.id||null}if(ok)await saveCredential(szerepkor,felhasznalo,clientHash,soforId)}
    if(!ok)return{siker:false,uzenet:"Hibás felhasználónév vagy jelszó."};
    const token=await issueSession(szerepkor,felhasznalo,soforId);let nev="";if(soforId){const{data:s}=await db.from("soforok").select("nev").eq("id",soforId).single();nev=s?.nev||legacy?.nev||""}return{siker:true,token,nev};
  }
  if (name === "onlineRendelesAllapot") {
    const { data } = await db.from("app_beallitasok").select("ertek").eq("kulcs","online_rendeles").maybeSingle();
    return { online: data?.ertek === true };
  }
  if (name === "cimJavaslatok") {
    const q = clean(p.keres, 180); if (q.length < 3) return { lista: [] };
    const qLower=q.toLocaleLowerCase("hu-HU");
    const variants:string[]=[q];
    // A normál keresés megmarad; mellé tanyás, POI és hrsz alakokat próbálunk.
    if(/közép\s*tanya/i.test(q)) variants.push(q.replace(/közép\s*tanya/i,"Középcebe tanya"));
    if(/szerencse.*(vendég|vendegh)/i.test(qLower)||qLower.replace(/[\s-]+/g,"").includes("szerencsecsillagvendégház")||qLower.replace(/[\s-]+/g,"").includes("szerencsecsillagvendeghaz")) variants.push("Szerencsecsillag Vendégház Kiskőrös","Középcebe tanya 50/2 Kiskőrös");
    const hrsz=q.match(/(?:hrsz\.?\s*)?(0?\d+(?:\/\d+)?)(?:\s*hrsz\.?)?/i)?.[1]||"";
    if(hrsz){
      const telep=(q.match(/\b(Kiskőrös|Soltvadkert|Akasztó|Kaskantyú|Páhi|Tabdi|Csengőd|Bócsa|Kecel|Izsák|Kecskemét)\b/i)?.[1]||"Kiskőrös");
      variants.push(`${telep} ${hrsz} hrsz`,`${telep} ${hrsz}`);
    }
    if(!/(kiskőrös|kecskemét|soltvadkert|akasztó|kaskantyú|páhi|tabdi|csengőd|bócsa|kecel|izsák)/i.test(q)) variants.push("Kiskőrös "+q);
    let all:any[]=[];
    async function nom(v:string,extra=""){
      const alap=`format=json&countrycodes=hu&limit=20&addressdetails=1&namedetails=1&extratags=1&accept-language=hu&${extra}q=${encodeURIComponent(v)}`;
      let r=await fetch(`https://nominatim.openstreetmap.org/search?${alap}&viewbox=18.8,46.95,19.8,46.30&bounded=1`,{headers:{"User-Agent":"AutoberlesSoforrel/1.0"}});
      let a=r.ok?await r.json():[];
      if(!Array.isArray(a)||!a.length){r=await fetch(`https://nominatim.openstreetmap.org/search?${alap}`,{headers:{"User-Agent":"AutoberlesSoforrel/1.0"}});a=r.ok?await r.json():[]}
      if(Array.isArray(a))all.push(...a);
    }
    for(const v of [...new Set(variants)]) await nom(v);
    // Helynév / vendégház / étterem / bolt stb. POI-kat is külön próbáljuk.
    if(!/\d/.test(q)||/(vendég|hotel|panzió|étterem|bolt|áruház|iskola|óvoda|kocsma|csárda|tanya|major|farm)/i.test(q)){
      try{
        const r=await fetch(`https://nominatim.openstreetmap.org/search?format=json&countrycodes=hu&limit=20&addressdetails=1&namedetails=1&extratags=1&accept-language=hu&layer=poi,address&viewbox=18.8,46.95,19.8,46.30&q=${encodeURIComponent(q)}`,{headers:{"User-Agent":"AutoberlesSoforrel/1.0"}});
        const a=r.ok?await r.json():[];if(Array.isArray(a))all.push(...a)
      }catch{}
    }
    const seen=new Set<string>();all=all.filter((x:any)=>{const k=String(x.place_id||((x.osm_type||"")+"-"+(x.osm_id||""))||x.display_name);if(seen.has(k))return false;seen.add(k);return true});
    const tav=(x:any)=>{const lat=Number(x.lat),lon=Number(x.lon),dLat=(lat-46.6214)*Math.PI/180,dLon=(lon-19.2850)*Math.PI/180,p1=46.6214*Math.PI/180,p2=lat*Math.PI/180,h=Math.sin(dLat/2)**2+Math.cos(p1)*Math.cos(p2)*Math.sin(dLon/2)**2;return 6371*2*Math.atan2(Math.sqrt(h),Math.sqrt(1-h))};
    let list=all.sort((x:any,y:any)=>tav(x)-tav(y));
    const hm=q.match(/(?:^|\s)(\d+(?:\s*\/\s*\d+|[A-Za-z])?)(?:\s*$)/)?.[1]?.replace(/\s+/g,"")||"";
    return { lista:list.slice(0,10).map((x:any)=>{let cim=shortAddress(x);const aa=x?.address||{};const cons=aa.conscriptionnumber||x?.extratags?.["addr:conscriptionnumber"]||"";if(hm&&!String(aa.house_number||"").trim()&&!cons){const city=aa.city||aa.town||aa.village||aa.municipality||aa.hamlet||"",road=aa.road||aa.pedestrian||aa.residential||aa.street||aa.place||aa.hamlet||"";if(city&&road)cim=city+", "+road+" "+hm}if(cons&&!cim.includes(String(cons)))cim=(cim?cim+" • ":"")+String(cons)+" hrsz";const poi=x?.namedetails?.name||x?.name||aa.shop||aa.amenity||aa.tourism||aa.office||aa.building||aa.leisure||aa.name||"";const nev=String(poi||"").trim();if(nev&&!cim.toLowerCase().includes(nev.toLowerCase()))cim=nev+" – "+cim;return{cim}}) };
  }
  if (name === "foglalasKuldes") {
    let a:any={}; try{a=JSON.parse(decodeURIComponent(String(p.adat||"{}")))}catch{}
    const email=clean(a.email,240).toLowerCase(),telefon=clean(a.telefon,60);
    if(!email.includes("@")||clean(a.nev,160).length<2||clean(a.indulas).length<3||clean(a.cel).length<3)return{siker:false,uzenet:"Tölts ki minden kötelező mezőt!"};
    const {data:blocked}=await db.from("tiltolista").select("id").or(`and(tipus.eq.email,ertek.eq.${email}),and(tipus.eq.telefon,ertek.eq.${telefon})`).limit(1);
    if(blocked?.length)return{siker:false,uzenet:"Erről az elérhetőségről nem adható le rendelés."};
    const azonosito=id(),planned=a.rendelesTipus==="idopont",datum=planned&&a.datum?a.datum:new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date());
    if(!planned){
      const {data:working}=await db.from("soforok").select("id").eq("aktiv",true).eq("dolgozik",true);
      if(!working?.length)return{siker:false,uzenet:"Jelenleg nincs szolgálatban elérhető sofőr."};
      // A "Minél hamarabb" rendelést nem blokkoljuk attól, hogy a dolgozó sofőrnek már van aktív fuvarja.
      // A sorhelyet és a várható érkezést a meglévő sor/ETA logika számolja a megerősítés után.
    }
    if(planned&&a.datum&&a.ido){
      const target:any={datum,ido:clean(a.ido,8),indulas:clean(a.indulas),cel:clean(a.cel)};
      const targetMs=tripPlannedMs(target);
      const {data:working}=await db.from("soforok").select("id").eq("aktiv",true).eq("dolgozik",true);
      if(!working?.length)return{siker:false,uzenet:"Erre az időpontra jelenleg nincs szolgálatban elérhető sofőr."};
      const nowMs=Date.now();
      let vanSzabad=false;
      for(const d of working){
        const {data:jobs}=await db.from("fuvarok").select("id,indulas,cel,datum,ido,letrehozva,statusz").eq("sofor_id",d.id).eq("statusz","Elvállalva").order("letrehozva");
        const {data:waiting}=await db.from("fuvarok").select("id,indulas,cel,datum,ido,letrehozva,statusz").in("statusz",["Új rendelés","Megerősítésre vár"]).lte("letrehozva",new Date().toISOString()).order("letrehozva");
        const chain=[...(jobs||[]),...(waiting||[]).filter((x:any)=>!x.ido||((tripPlannedMs(x)??Infinity)<(targetMs??0)))];
        let availableAt=nowMs,lastDest:string|null=null,ok=true;
        for(const j of chain){
          if(lastDest){const hop=await routeMinutes(lastDest,j.indulas);if(!hop){ok=false;break}availableAt+=hop*60000}
          const ride=await routeMinutes(j.indulas,j.cel);if(!ride){ok=false;break}availableAt+=ride*60000;lastDest=j.cel;
        }
        if(ok&&lastDest){const hop=await routeMinutes(lastDest,target.indulas);if(!hop)ok=false;else availableAt+=hop*60000}
        if(ok&&targetMs!==null&&availableAt<=targetMs){vanSzabad=true;break}
      }
      if(!vanSzabad)return{siker:false,uzenet:"Erre az időpontra a jelenlegi fuvarok menetideje alapján nincs szabad sofőr. Válassz későbbi időpontot."};
    }
    const {data:f,error}=await db.from("fuvarok").insert({azonosito,nev:clean(a.nev,160),telefon,email,indulas:clean(a.indulas),cel:clean(a.cel),datum,ido:planned?clean(a.ido,8)||null:null,utasok:Math.max(1,Math.min(9,Number(a.utasok)||1)),megjegyzes:clean(a.megjegyzes,2000),statusz:"Megerősítésre vár"}).select("id,azonosito").single();
    if(error||!f)return{siker:false,uzenet:"A rendelést nem sikerült rögzíteni."};
    const raw=randomHex(32),hash=await sha256(raw);
    const {error:te}=await db.from("booking_confirmation_tokens").insert({fuvar_id:f.id,token_hash:hash,expires_at:new Date(Date.now()+24*3600*1000).toISOString()});
    if(te){await db.from("fuvarok").delete().eq("id",f.id);return{siker:false,uzenet:"A megerősítő linket nem sikerült létrehozni."};}
    const link="https://autoberlessoforrelkiskoros.hu/megerosites/?token="+encodeURIComponent(raw);
    try{await sendMail(email,"Fuvarrendelés megerősítése",`<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto"><h2>Autóbérlés sofőrrel - Kiskőrös</h2><p>Szia ${esc(a.nev)}!</p><p>A rendelésed elküldéséhez erősítsd meg az email címed.</p><p><a href="${link}" style="display:inline-block;background:#ffc400;color:#111827;padding:14px 20px;border-radius:10px;text-decoration:none;font-weight:bold">RENDELÉS MEGERŐSÍTÉSE</a></p><p>Azonosító: <b>${azonosito}</b></p><p>Indulás: ${esc(a.indulas)}<br>Cél: ${esc(a.cel)}</p><p>A link 24 óráig érvényes.</p></div>`)}catch(e){console.error(e);await db.from("fuvarok").delete().eq("id",f.id);return{siker:false,uzenet:"A megerősítő emailt nem sikerült elküldeni. Próbáld újra!"};}
    return{siker:true,foglalasiAzonosito:azonosito,uzenet:"Elküldtük a megerősítő emailt."};
  }
  if(name==="foglalasEmailMegerositese"){
    const tok=clean(p.args?.[0]||p.token,200);if(!tok)return{siker:false,uzenet:"Hiányzó vagy hibás megerősítő link."};
    const h=await sha256(tok),now=new Date().toISOString();
    const {data:t}=await db.from("booking_confirmation_tokens").select("id,fuvar_id,expires_at,used_at").eq("token_hash",h).maybeSingle();
    if(!t||t.used_at||t.expires_at<=now)return{siker:false,uzenet:"A megerősítő link hibás, lejárt, vagy már felhasználtad."};
    const {data:f,error}=await db.from("fuvarok").update({statusz:"Új rendelés"}).eq("id",t.fuvar_id).eq("statusz","Megerősítésre vár").select("*").maybeSingle();
    if(error||!f)return{siker:false,uzenet:"A rendelés nem található, vagy már megerősítetted."};
    await db.from("booking_confirmation_tokens").update({used_at:now}).eq("id",t.id).is("used_at",null);
    await db.from("fuvar_esemenyek").insert({azonosito:f.azonosito,tipus:"uj_fuvar"});
    await notifyWorkingDrivers(f);
    return{siker:true,uzenet:"A rendelésed megerősítése sikerült.",foglalasiAzonosito:f.azonosito,azonosito:f.azonosito};
  }
  if (name === "utasRendelesLemondas") {
    const az=clean(p.id||p.azonosito||p.args?.[0],120);
    if(!az)return{siker:false,uzenet:"Hiányzó rendelési azonosító."};
    const {data:f}=await db.from("fuvarok").select("id,statusz").eq("azonosito",az).maybeSingle();
    if(!f)return{siker:false,uzenet:"A rendelés nem található."};
    if(!["Új rendelés","Elvállalva"].includes(f.statusz))return{siker:false,uzenet:"Ez a rendelés már nem mondható le."};
    await db.from("fuvar_helyzet").delete().eq("fuvar_id",f.id);
    const {error}=await db.from("fuvarok").delete().eq("id",f.id);
    return error?{siker:false,uzenet:"A rendelést nem sikerült lemondani."}:{siker:true,uzenet:"A rendelés sikeresen lemondva."};
  }
  if (name === "utasAppKovetes") {
    const az = clean(p.id || p.azonosito || p.args?.[0],120);
    const { data } = await db.from("fuvarok").select("*").eq("azonosito",az).maybeSingle();
    if (!data) return { siker:false,uzenet:"A rendelés nem található." };
    let auto:any=null;if(data.sofor_id){const {data:sd}=await db.from("soforok").select("nev,auto_tipus,auto_szin,rendszam").eq("id",data.sofor_id).maybeSingle();auto=sd} refreshEtaBg(); return { siker:true,...normalizeTrip(data),sofor:data.sofor_nev||auto?.nev||null,autoTipus:auto?.auto_tipus||null,autoSzin:auto?.auto_szin||null,rendszam:auto?.rendszam||null,menetido:data.menetido_perc,erkezes:data.varhato_erkezes,sorban:data.sorban,varakozasPerc:data.menetido_perc,ajanlottSofor:data.ajanlott_sofor_nev||null };
  }
  if (name === "tripLocation") {
    const az=clean(p.azonosito||p.id,120);
    const {data:f}=await db.from("fuvarok").select("id,sofor_nev").eq("azonosito",az).eq("statusz","Elvállalva").maybeSingle();
    if(!f)return{siker:false};
    const {data:h}=await db.from("fuvar_helyzet").select("lat,lng,frissitve").eq("fuvar_id",f.id).gte("frissitve",new Date(Date.now()-180000).toISOString()).maybeSingle();
    return h?{siker:true,...h,sofor_nev:f.sofor_nev}:{siker:false};
  }
  if (name === "ertekelesKuldes") {
    let a:any = p.adat || p.args?.[0] || p;
    if (typeof a === "string") { try { a = JSON.parse(decodeURIComponent(a)); } catch { a = {}; } }
    const cs = Math.max(1,Math.min(5,Number(a.csillag)||0)); if (!cs) return { siker:false,uzenet:"Válassz csillagot!" };
    const { error } = await db.from("ertekelesek").insert({ nev:clean(a.nev,160)||"Névtelen",velemeny:clean(a.velemeny,2000),csillag:cs,allapot:"Függőben",datum:new Date().toLocaleDateString("hu-HU") });
    return error ? {siker:false,uzenet:"Nem sikerült elküldeni."}:{siker:true,uzenet:"Köszönjük az értékelést!"};
  }
  if (name === "ertekelesBetoltes" || name === "ertekelesekLekerdezese") {
    const { data } = await db.from("ertekelesek").select("nev,velemeny,csillag,datum").eq("allapot","Jóváhagyva").order("id",{ascending:false});
    return { siker:true,lista:data || [] };
  }
  return { siker:false,uzenet:"Ismeretlen művelet." };
}

async function customerAction(name:string,args:any[],token:string) {
  const r = await role(token); if (!r || r.szerepkor === "sofor") return {siker:false,uzenet:"A munkamenet lejárt."};
  let customerId = r.ugyfel_id;
  if (!customerId) {
    const { data } = await db.from("ugyfelek").select("id").eq("email",r.email).maybeSingle(); customerId=data?.id;
    if (customerId) await db.from("app_roles").update({ugyfel_id:customerId}).eq("user_id",r.user_id);
  }
  if (name === "torzsProfilLekerdezese") {
    const { data:u } = await db.from("ugyfelek").select("*").eq("id",customerId).maybeSingle();
    const { data:n } = await db.from("pont_naplo").select("pont,tipus,megjegyzes,letrehozva").eq("ugyfel_id",customerId).order("letrehozva",{ascending:false});
    return {siker:true,profil:{id:u?.id,nev:u?.nev||r.user.user_metadata?.nev||"",telefon:u?.telefon||r.user.user_metadata?.telefon||"",email:r.email,pont:u?.pont||0,teljesitettFuvar:u?.teljesitett_fuvar||0,szint:u?.szint||"Bronz"},naplo:(n||[]).map((x:any)=>({...x,datum:new Date(x.letrehozva).toLocaleDateString("hu-HU")}))};
  }
  if (name === "torzsSajatFuvarok") {
    const { data } = await db.from("fuvarok").select("*").eq("email",r.email).order("letrehozva",{ascending:false});
    const lista=(data||[]).map(normalizeTrip); return {siker:true,aktiv:lista.filter((x:any)=>["Megerősítésre vár","Új rendelés","Elvállalva"].includes(x.statusz)),elozo:lista.filter((x:any)=>!["Megerősítésre vár","Új rendelés","Elvállalva"].includes(x.statusz)),lista};
  }
  if (name === "torzsPontBevaltas") {
    const n=Math.floor(Number(args[1]??args[0])); const {data:u}=await db.from("ugyfelek").select("pont").eq("id",customerId).single();
    if (!n||n<1||Number(u?.pont||0)<n) return {siker:false,uzenet:"Nincs elég pontod."};
    await db.from("ugyfelek").update({pont:Number(u.pont)-n,frissitve:new Date().toISOString()}).eq("id",customerId);
    await db.from("pont_naplo").insert({ugyfel_id:customerId,pont:-n,tipus:"Beváltás",megjegyzes:"Pontbeváltás"});
    return {siker:true,uzenet:`${n} pont beváltva.`};
  }
  if (name === "torzsKijelentkezes") return {siker:true};
  if (name === "confirmBooking") {
    const az=clean(args[0],120);
    const {data,error}=await db.from("fuvarok").update({statusz:"Új rendelés"}).eq("azonosito",az).eq("email",r.email).eq("statusz","Megerősítésre vár").select("azonosito").maybeSingle();
    if(data)await db.from("fuvar_esemenyek").insert({azonosito:data.azonosito,tipus:"uj_fuvar"});
    return error||!data?{siker:false,uzenet:"A rendelés nem található, vagy már megerősítetted."}:{siker:true,azonosito:az};
  }
  return {siker:false,uzenet:"Ismeretlen művelet."};
}

function tripPlannedMs(f:any){if(!f?.datum||!f?.ido)return null;const t=String(f.ido).slice(0,8);return new Date(`${f.datum}T${t}+02:00`).getTime()}
async function tripConflict(target:any,assigned:any[]){
 const t=tripPlannedMs(target);if(!t)return false;
 for(const x of assigned){
  const xt=tripPlannedMs(x);if(xt===null)continue;
  const ride=await routeMinutes(x.indulas,x.cel);if(!ride)continue;
  const toNext=await routeMinutes(x.cel,target.indulas);
  const xEnd=xt+(ride+(toNext||0))*60000;
  if(t>=xt&&t<xEnd)return true;
  if(t<xt){
   const targetRide=await routeMinutes(target.indulas,target.cel);if(!targetRide)continue;
   const toExisting=await routeMinutes(target.cel,x.indulas);
   const targetEnd=t+(targetRide+(toExisting||0))*60000;
   if(targetEnd>xt)return true;
  }
 }
 return false
}
async function driverAction(name:string,args:any[],token:string) {
  const r=await role(token,"sofor"); if(!r) return {siker:false,uzenet:"A munkamenet lejárt."};
  const {data:s}=await db.from("soforok").select("*").eq("id",r.sofor_id).single();
  if(name==="soforKovetkezoSzabad"){
    const {data:drivers}=await db.from("soforok").select("id,nev").eq("aktiv",true).eq("dolgozik",true);
    if(!drivers?.length)return{siker:true,elerheto:false,uzenet:"Nincs szolgálatban sofőr."};
    const today=new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date());
    const {data:rows}=await db.from("fuvarok").select("id,indulas,cel,datum,ido,letrehozva,statusz,sofor_id,menetido_perc").in("statusz",["Új rendelés","Elvállalva"]).gte("datum",today).order("letrehozva");
    let best:any=null;
    for(let di=0;di<drivers.length;di++){
      const d=drivers[di],assigned=(rows||[]).filter((x:any)=>x.statusz==="Elvállalva"&&x.sofor_id===d.id),waiting=(rows||[]).filter((x:any)=>x.statusz==="Új rendelés"),queued=waiting.filter((_:any,wi:number)=>wi%drivers.length===di),jobs=[...assigned,...queued];
      let mins=0;
      for(const j of jobs){const m=Number(j.menetido_perc)||0;mins+=m>0?m:30}
      if(!best||mins<best.perc)best={nev:d.nev,perc:mins};
    }
    return best?{siker:true,elerheto:true,nev:best.nev,perc:best.perc}:{siker:true,elerheto:false,uzenet:"A várható felszabadulás most nem számolható."};
  }
  if(name==="soforSajatDolgozikAllapot") return {siker:true,dolgozik:!!s.dolgozik};
  if(name==="soforSajatDolgozikValtas"){await db.from("soforok").update({dolgozik:!s.dolgozik,frissitve:new Date().toISOString()}).eq("id",s.id);refreshEtaBg();return{siker:true,dolgozik:!s.dolgozik};}
  if(name==="ujFuvarokLekerdezese"||name==="soforKezdoAdatok"){
    const {data}=await db.from("fuvarok").select("*").in("statusz",["Új rendelés","Elvállalva"]).gte("datum",new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date())).order("datum").order("ido",{nullsFirst:true});
    const aktiv=data||[];
    const visible=aktiv;
    const {data:working}=await db.from("soforok").select("id,nev").eq("aktiv",true).eq("dolgozik",true).order("nev");
    const load=new Map<string,number>(); for(const x of aktiv){if(x.statusz==="Elvállalva"&&x.sofor_id)load.set(x.sofor_id,(load.get(x.sofor_id)||0)+1)}
    const ranked=(working||[]).map((d:any)=>({...d,db:load.get(d.id)||0})).sort((a:any,b:any)=>a.db-b.db||String(a.nev).localeCompare(String(b.nev),"hu"));
    const visszaigazolt=new Set<string>();const vaz=visible.map((x:any)=>x.azonosito).filter(Boolean);if(vaz.length){const{data:ve}=await db.from("fuvar_esemenyek").select("azonosito").in("azonosito",vaz).eq("tipus","rendeles_megkapva");for(const e of ve||[])visszaigazolt.add(e.azonosito)}
    refreshEtaBg();
    const lista:any[]=visible.map((x:any)=>{
      const n:any=normalizeTrip(x);n.rendelesVisszaigazolva=visszaigazolt.has(x.azonosito);
      n.varakozasPerc=x.menetido_perc??null;n.sorban=x.sorban??null;
      if(x.statusz==="Új rendelés"&&x.ajanlott_sofor_nev)n.ajanlas={nev:x.ajanlott_sofor_nev,szabad:Number(x.sorban)>1?"Fuvarban":"Most szabad",indok:Number.isFinite(Number(x.menetido_perc))?"Várható felvétel: kb. "+Number(x.menetido_perc)+" perc":""};
      return n;
    });
    return name==="soforKezdoAdatok"?{siker:true,nev:s.nev,dolgozik:!!s.dolgozik,munka:{siker:true,dolgozik:!!s.dolgozik},fuvarok:lista}:{siker:true,lista};
  }
  if(name==="fuvarElvallalasa"||name==="fuvarKesz"){
    const fid=await tripByRow(args[0],true); if(!fid)return{siker:false,uzenet:"A fuvar nem található."};
    if(name==="fuvarElvallalasa"){
      const {data:target}=await db.from("fuvarok").select("*").eq("id",fid).maybeSingle();const force=args[1]===true||args[1]==="true"||args[1]===1;const {data:earlier}=await db.from("fuvarok").select("id,azonosito,letrehozva").eq("statusz","Új rendelés").lt("letrehozva",target?.letrehozva||new Date().toISOString()).order("letrehozva").limit(1);if(earlier?.length&&!force)return{siker:false,kihagyas:true,uzenet:"Van előtte várakozó rendelés. Biztosan ki szeretnéd hagyni és ezt a fuvart elvállalni?"};const {data:mine}=await db.from("fuvarok").select("id,datum,ido,statusz").eq("sofor_id",s.id).eq("statusz","Elvállalva");if(target&&await tripConflict(target,mine||[]))return{siker:false,uzenet:"A meglévő fuvarod menetideje miatt erre az időpontra nem tudsz odaérni. Válassz másik fuvart."};
      const {data,error}=await db.from("fuvarok").update({statusz:"Elvállalva",sofor_id:s.id,sofor_nev:s.nev}).eq("id",fid).eq("statusz","Új rendelés").select("azonosito,email,nev,indulas,cel").maybeSingle();
      if(error||!data)return{siker:false,uzenet:"Ezt a fuvart már elvállalták."};
      await db.from("fuvar_esemenyek").insert({azonosito:data.azonosito,tipus:"fuvar_elvallalva"});
      try{const {data:admins}=await db.from("app_roles").select("email").eq("szerepkor","admin");for(const a of admins||[]){if(clean(a.email,240).includes("@"))await sendMail(a.email,"Fuvar elvállalva",`<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto"><h2>Fuvar elvállalva</h2><p><b>${esc(s.nev)}</b> elvállalta a rendelést.</p><p><b>Indulás:</b> ${esc(data.indulas)}<br><b>Cél:</b> ${esc(data.cel)}<br><b>Azonosító:</b> ${esc(data.azonosito)}</p><p style="font-size:12px;color:#666">Automatikus szolgáltatási értesítés az Autóbérlés sofőrrel rendszerből.</p></div>`)}}catch(e){console.error("admin accepted email",e)}
      if(clean(data.email,240).includes("@"))try{const link="https://autoberlessoforrelkiskoros.hu/kovetes/?id="+encodeURIComponent(data.azonosito);const {data:sd}=await db.from("soforok").select("auto_tipus,auto_szin,rendszam").eq("id",s.id).maybeSingle();await sendMail(data.email,"A sofőr elvállalta a fuvarodat",`<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto"><h2>A fuvarodat elvállalták</h2><p>Kedves ${esc(data.nev)}!</p><p><b>Sofőr:</b> ${esc(s.nev)}<br><b>Autó:</b> ${esc(sd?.auto_tipus||"")} ${esc(sd?.auto_szin||"")}<br><b>Rendszám:</b> ${esc(sd?.rendszam||"")}</p><p>Indulás: ${esc(data.indulas)}<br>Cél: ${esc(data.cel)}</p><p><a href="${link}" style="display:inline-block;background:#ffc400;color:#111827;padding:14px 20px;border-radius:10px;text-decoration:none;font-weight:800">SOFŐR ÉLŐ KÖVETÉSE</a></p><p>A linken láthatod a sorszámodat, a becsült várakozási időt és az élő helyzetet.</p></div>`)}catch(e){console.error("customer accepted email",e)}
      const accepted={...target,statusz:"Elvállalva",sofor_id:s.id,sofor_nev:s.nev};
      try{const e=await etaDriver(s,accepted);if(e.mins!==null)await db.from("fuvarok").update({menetido_perc:e.mins,sorban:e.jobs+1,ajanlott_sofor_id:s.id,ajanlott_sofor_nev:s.nev,eta_frissitve:new Date().toISOString()}).eq("id",fid)}catch(e){console.error("ETA_ACCEPT",e)}
      refreshEtaBg();return{siker:true};
    }
    const {data:finished,error}=await db.from("fuvarok").update({statusz:"Kész"}).eq("id",fid).eq("sofor_id",s.id).eq("statusz","Elvállalva").select("*").maybeSingle();if(error||!finished)return{siker:false,uzenet:"A fuvar lezárása nem sikerült."};await awardRidePoints(finished);try{const {data:admins}=await db.from("app_roles").select("email").eq("szerepkor","admin");for(const a of admins||[]){if(clean(a.email,240).includes("@"))await sendMail(a.email,"Fuvar lezárva",`<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto"><h2>Fuvar lezárva</h2><p><b>${esc(s.nev)}</b> lezárta a fuvart.</p><p><b>Utas:</b> ${esc(finished.nev||"")}<br><b>Indulás:</b> ${esc(finished.indulas||"")}<br><b>Cél:</b> ${esc(finished.cel||"")}<br><b>Azonosító:</b> ${esc(finished.azonosito||"")}</p><p style="font-size:12px;color:#666">Automatikus szolgáltatási értesítés az Autóbérlés sofőrrel rendszerből.</p></div>`)}}catch(e){console.error("admin finished email",e)}return{siker:true};
  }
  if(name==="soforRendelesMegkapva"){
    const fid=await tripByRow(args[0],true);if(!fid)return{siker:false,uzenet:"A fuvar nem található."};
    const {data:f}=await db.from("fuvarok").select("id,azonosito,nev,email,indulas,cel,datum,ido,statusz").eq("id",fid).maybeSingle();
    if(!f||f.statusz!=="Új rendelés")return{siker:false,uzenet:"Ez a rendelés már nem vár visszaigazolásra."};
    if(!f.ido)return{siker:false,uzenet:"Ez a visszaigazolás csak időpontos rendelésnél használható."};
    if(!clean(f.email,240).includes("@"))return{siker:false,uzenet:"Ehhez a rendeléshez nincs email cím megadva."};
    try{await sendMail(f.email,"Rendelését megkaptuk",`<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto"><h2>Rendelését megkaptuk</h2><p>Szia ${esc(f.nev||"")}!</p><p>Visszaigazoljuk, hogy a rendelésedet <b>megkaptuk és elfogadtuk</b>.</p><p><b>Időpont:</b> ${esc(f.datum)} ${esc(String(f.ido||"").slice(0,5))}<br><b>Indulás:</b> ${esc(f.indulas)}<br><b>Cél:</b> ${esc(f.cel)}<br><b>Azonosító:</b> ${esc(f.azonosito)}</p><p>A sofőr elvállalásáról külön értesítést kapsz.</p><p style="font-size:12px;color:#666">Autóbérlés sofőrrel – Kiskőrös</p></div>`);await db.from("fuvar_esemenyek").insert({azonosito:f.azonosito,tipus:"rendeles_megkapva"});return{siker:true,uzenet:"A visszaigazolást elküldtük az ügyfélnek."}}catch(e){console.error("booking received email",e);return{siker:false,uzenet:"A visszaigazoló emailt nem sikerült elküldeni."}}
  }
  if(name==="soforAppHelyzetFrissites"){
    const [az,lat,lng]=args,nlat=Number(lat),nlng=Number(lng);if(!Number.isFinite(nlat)||!Number.isFinite(nlng))return{siker:false};
    let f:any=null;if(clean(az,120)&&clean(az,120)!=="__szabad__"){const q=await db.from("fuvarok").select("id").eq("azonosito",clean(az,120)).eq("sofor_id",s.id).eq("statusz","Elvállalva").maybeSingle();f=q.data}
    const stamp=new Date().toISOString();await db.from("sofor_helyzet").upsert({sofor_id:s.id,fuvar_id:f?.id||null,lat:nlat,lng:nlng,frissitve:stamp},{onConflict:"sofor_id"});
    if(f)await db.from("fuvar_helyzet").upsert({fuvar_id:f.id,lat:nlat,lng:nlng,frissitve:stamp});
    refreshEtaBg();return{siker:true};
  }
  if(name==="soforUgyfelJavaslatok") {const q=clean(args[0],100);const byKey=new Map<string,any>();const{data:reg}=await db.from("ugyfelek").select("id,nev,telefon,email").or(`nev.ilike.%${q}%,telefon.ilike.%${q}%`).limit(12);for(const u of reg||[]){const k=String(u.telefon||u.email||u.nev||"").trim().toLocaleLowerCase("hu-HU");if(k)byKey.set(k,{nev:u.nev,telefon:u.telefon,email:u.email})}const{data:hist}=await db.from("fuvarok").select("nev,telefon,email,indulas,cel,letrehozva").or(`nev.ilike.%${q}%,telefon.ilike.%${q}%`).order("letrehozva",{ascending:false}).limit(40);for(const f of hist||[]){const k=String(f.telefon||f.email||f.nev||"").trim().toLocaleLowerCase("hu-HU");if(k&&!byKey.has(k))byKey.set(k,{nev:f.nev,telefon:f.telefon,email:f.email})}const lista=[];for(const u of [...byKey.values()].slice(0,12)){let fs:any[]=[];if(u.telefon){const r=await db.from("fuvarok").select("indulas,cel").eq("telefon",u.telefon).order("letrehozva",{ascending:false}).limit(20);fs=r.data||[]}else if(u.email){const r=await db.from("fuvarok").select("indulas,cel").eq("email",u.email).order("letrehozva",{ascending:false}).limit(20);fs=r.data||[]}else{const r=await db.from("fuvarok").select("indulas,cel").eq("nev",u.nev).order("letrehozva",{ascending:false}).limit(20);fs=r.data||[]}const m=new Map();for(const f of fs)for(const cim of [f.indulas,f.cel])if(cim){const k=String(cim).trim();m.set(k,(m.get(k)||0)+1)}lista.push({nev:u.nev,telefon:u.telefon,email:u.email,cimek:[...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,6).map(([cim,alkalom])=>({cim,alkalom}))})}return{siker:true,lista};}
  if(name==="soforFuvarHozzaadas") {const a=args[0]||{}, az=id(),planned=a.rendelesTipus==="idopont";const datum=planned&&a.datum?a.datum:new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date());const{data:f,error}=await db.from("fuvarok").insert({azonosito:az,nev:clean(a.nev,160),telefon:clean(a.telefon,60),email:clean(a.email,240)||null,indulas:clean(a.indulas),cel:clean(a.cel),datum,ido:planned?(clean(a.ido,8)||null):null,utasok:Number(a.utasok)||1,megjegyzes:clean(a.megjegyzes,2000),statusz:"Új rendelés"}).select("*").single();if(!error&&f)await notifyWorkingDrivers(f);return error?{siker:false,uzenet:"Nem sikerült menteni: "+(error.message||"adatbázis hiba")}:{siker:true,uzenet:"Fuvar elmentve.",azonosito:az};}
  if(name==="soforKijelentkezes"){await db.from("login_sessions").delete().eq("token_hash",await sha256(token));return{siker:true};}
  return{siker:false,uzenet:"Ismeretlen művelet."};
}

async function adminAction(name:string,args:any[],token:string){
  const r=await role(token,"admin");if(!r)return{siker:false,uzenet:"A munkamenet lejárt."};
  if(name==="onlineRendelesAllapot"){const{data}=await db.from("app_beallitasok").select("ertek").eq("kulcs","online_rendeles").single();return{online:data.ertek===true};}
  if(name==="onlineRendelesValtas"){const{data}=await db.from("app_beallitasok").select("ertek").eq("kulcs","online_rendeles").single();await db.from("app_beallitasok").update({ertek:!(data.ertek===true),frissitve:new Date().toISOString()}).eq("kulcs","online_rendeles");return{siker:true};}
  if(name==="adminNapiOsszesito"){const ma=new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date()),tipus=clean(args[0]||"nap",20),kertDatum=clean(args[1]||ma,20);let tol=kertDatum,ig=kertDatum;if(tipus==="het"){const d=new Date(kertDatum+"T12:00:00Z"),wd=(d.getUTCDay()+6)%7;d.setUTCDate(d.getUTCDate()-wd);tol=d.toISOString().slice(0,10);d.setUTCDate(d.getUTCDate()+6);ig=d.toISOString().slice(0,10)}else if(tipus==="honap"){tol=kertDatum.slice(0,7)+"-01";const d=new Date(tol+"T12:00:00Z");d.setUTCMonth(d.getUTCMonth()+1);d.setUTCDate(0);ig=d.toISOString().slice(0,10)}const{data:fs}=await db.from("fuvarok").select("azonosito,statusz,sofor_nev,letrehozva,datum,ido").gte("datum",tol).lte("datum",ig);const lista=fs||[],azok=lista.map((x:any)=>x.azonosito).filter(Boolean);let es:any[]=[];if(azok.length){const{data}=await db.from("fuvar_esemenyek").select("azonosito,tipus,letrehozva").in("azonosito",azok).in("tipus",["uj_fuvar","fuvar_elvallalva"]);es=data||[]}const created=new Map(),accepted=new Map();for(const e of es){const m=e.tipus==="uj_fuvar"?created:accepted;if(!m.has(e.azonosito))m.set(e.azonosito,new Date(e.letrehozva).getTime())}let sum=0,n=0;for(const x of lista){if(x.ido)continue;const a=accepted.get(x.azonosito),u=new Date(x.letrehozva).getTime();if(a&&u&&a>=u){sum+=(a-u)/60000;n++}}const sofor:any={};for(const x of lista)if(x.statusz==="Kész"&&x.sofor_nev)sofor[x.sofor_nev]=(sofor[x.sofor_nev]||0)+1;return{siker:true,datum:kertDatum,tipus,tol,ig,osszes:lista.length,kesz:lista.filter((x:any)=>x.statusz==="Kész").length,folyamatban:lista.filter((x:any)=>x.statusz==="Elvállalva").length,uj:lista.filter((x:any)=>x.statusz==="Új rendelés").length,megerositesreVar:lista.filter((x:any)=>x.statusz==="Megerősítésre vár").length,atlagVarakozasPerc:n?Math.round(sum/n):null,varakozasMinta:n,soforok:Object.entries(sofor).map(([nev,db])=>({nev,db}))};}
  if(name==="adminSoforListaLekerdezese"){const{data}=await db.from("soforok").select("*").eq("aktiv",true).order("nev");return(data||[]).map((x:any)=>({felhasznalo:x.felhasznalo,nev:x.nev,email:x.email,dolgozik:x.dolgozik,autoTipus:x.auto_tipus,autoSzin:x.auto_szin,rendszam:x.rendszam}));}
  if(name==="adminSoforHelyzetek"){const {data:fs}=await db.from("fuvarok").select("id,sofor_id,sofor_nev").eq("statusz","Elvállalva");const ids=(fs||[]).map((x:any)=>x.id);if(!ids.length)return[];const {data:hs}=await db.from("fuvar_helyzet").select("fuvar_id,lat,lng,frissitve").in("fuvar_id",ids).gte("frissitve",new Date(Date.now()-600000).toISOString());return(hs||[]).map((h:any)=>{const f=(fs||[]).find((x:any)=>x.id===h.fuvar_id);return{sofor:f?.sofor_nev||"",lat:h.lat,lng:h.lng,frissitve:h.frissitve}})}
  if(name==="adminFuvarokLekerdezese"){const{data}=await db.from("fuvarok").select("*").in("statusz",["Megerősítésre vár","Új rendelés","Elvállalva"]).order("datum").order("ido",{nullsFirst:true});return(data||[]).map(normalizeTrip);}
  if(name==="adminErtekelesLista"){const{data}=await db.from("ertekelesek").select("*").order("id",{ascending:false});return(data||[]).map((x:any)=>({...x,sor:x.legacy_sor||x.id}));}
  if(name==="adminTiltolistaLekerdezese"){const{data}=await db.from("tiltolista").select("*").order("letrehozva",{ascending:false});return data||[];}
  if(name==="adminFelhasznaloLista"){const{data}=await db.from("ugyfelek").select("*").order("nev");return{siker:true,lista:(data||[]).map((x:any)=>({...x,teljesitettFuvar:x.teljesitett_fuvar}))};}
  if(name==="adminSoforDolgozikValtas"){const u=clean(args[0],120),{data}=await db.from("soforok").select("dolgozik").eq("felhasznalo",u).single();await db.from("soforok").update({dolgozik:!data.dolgozik}).eq("felhasznalo",u);return{siker:true};}
  if(name==="adminSoforEmailMentese"){await db.from("soforok").update({email:clean(args[1],240).toLowerCase()}).eq("felhasznalo",clean(args[0],120));return{siker:true,uzenet:"Email elmentve."};}
  if(name==="adminSoforJarmuMentese"){await db.from("soforok").update({auto_tipus:clean(args[1],160),auto_szin:clean(args[2],80),rendszam:clean(args[3],40)}).eq("felhasznalo",clean(args[0],120));return{siker:true,uzenet:"Jármű elmentve."};}
  if(name==="adminSoforLetrehozasa"){const[u,pw,email,auto,szin,rsz]=[clean(args[1],120).toLowerCase(),clean(args[2],128),args[3],args[4],args[5],args[6]];const{data:s,error}=await db.from("soforok").insert({nev:clean(args[0],160),felhasznalo:u,email:clean(email,240).toLowerCase(),auto_tipus:clean(auto,160),auto_szin:clean(szin,80),rendszam:clean(rsz,40)}).select("id").single();if(!error&&/^[a-f0-9]{64}$/.test(pw))await saveCredential("sofor",u,pw,s.id);return error?{siker:false,uzenet:error.message}:{siker:true,uzenet:"Sofőr hozzáadva."};}
  if(name==="adminSoforTorlese"){await db.from("soforok").update({aktiv:false,dolgozik:false}).eq("felhasznalo",clean(args[0],120));return{siker:true,uzenet:"Sofőr törölve."};}
  if(name==="adminFuvarMentese"){const a=args[0]||{},fid=await tripByRow(a.sor);if(!fid)return{siker:false,uzenet:"Nincs ilyen fuvar."};const sn=clean(a.sofor,160);let sid=null;if(sn){const{data:sd}=await db.from("soforok").select("id").eq("nev",sn).eq("aktiv",true).maybeSingle();sid=sd?.id||null}const{error}=await db.from("fuvarok").update({nev:clean(a.nev,160),telefon:clean(a.telefon,60),email:clean(a.email,240)||null,indulas:clean(a.indulas),cel:clean(a.cel),datum:a.datum,ido:a.ido||null,utasok:Number(a.utasok)||1,statusz:clean(a.statusz,80),sofor_nev:sn||null,sofor_id:sid,megjegyzes:clean(a.megjegyzes,2000)}).eq("id",fid);return error?{siker:false,uzenet:"Nem sikerült módosítani."}:{siker:true,uzenet:"Fuvar módosítva."};}
  if(name==="adminFuvarArchivum"){const{data}=await db.from("fuvarok").select("*").in("statusz",["Kész","Lemondva","Törölve"]).order("datum",{ascending:false}).order("ido",{ascending:false,nullsFirst:true}).limit(150);return{siker:true,lista:(data||[]).map(normalizeTrip)};}
  if(name==="adminFuvarVisszahelyezese"){const fid=await tripByRow(args[0]);if(!fid)return{siker:false,uzenet:"A fuvar nem található."};const{data,error}=await db.from("fuvarok").update({statusz:"Új rendelés",sofor_id:null,sofor_nev:null,varhato_erkezes:null}).eq("id",fid).in("statusz",["Kész","Lemondva","Törölve"]).select("azonosito").maybeSingle();if(error||!data)return{siker:false,uzenet:"A fuvart nem sikerült visszahelyezni."};await db.from("fuvar_esemenyek").insert({azonosito:data.azonosito,tipus:"uj_fuvar"});return{siker:true,uzenet:"Fuvar visszahelyezve az aktív rendelések közé."};}
  if(name==="adminFuvarTorlese"){const fid=await tripByRow(args[0]);if(!fid)return{siker:false,uzenet:"A fuvar nem található."};const{error}=await db.from("fuvarok").update({statusz:"Törölve",sofor_id:null,sofor_nev:null}).eq("id",fid);return error?{siker:false,uzenet:"Nem sikerült törölni."}:{siker:true,uzenet:"Fuvar törölve. A Visszahelyezés fülről szükség esetén helyreállítható."};}
  if(name==="adminErtekelesAllapot"){await db.from("ertekelesek").update({allapot:args[1]?"Jóváhagyva":"Függőben"}).or(`id.eq.${Number(args[0])},legacy_sor.eq.${Number(args[0])}`);return{siker:true,uzenet:"Értékelés frissítve."};}
  if(name==="adminErtekelesTorles"){await db.from("ertekelesek").delete().or(`id.eq.${Number(args[0])},legacy_sor.eq.${Number(args[0])}`);return{siker:true};}
  if(name==="adminUgyfelTiltasa"){const a=args[0]||{};await db.from("tiltolista").upsert({tipus:a.tipus,ertek:clean(a.ertek,240).toLowerCase()},{onConflict:"tipus,ertek"});return{siker:true,uzenet:"Tiltás elmentve."};}
  if(name==="adminTiltoFeloldasa"){await db.from("tiltolista").delete().eq("id",args[0]);return{siker:true};}
  if(name==="adminFelhasznaloPont"){const email=clean(args[0],240).toLowerCase(),n=Math.floor(Number(args[1]));const{data:u}=await db.from("ugyfelek").select("id,pont").eq("email",email).single();await db.from("ugyfelek").update({pont:Math.max(0,Number(u.pont)+n)}).eq("id",u.id);await db.from("pont_naplo").insert({ugyfel_id:u.id,pont:n,tipus:"Admin",megjegyzes:clean(args[2],500)});return{siker:true,uzenet:"Pontok frissítve."};}
  if(name==="adminFelhasznaloSzerkesztes"){const a=args[1]||{};await db.from("ugyfelek").update({nev:clean(a.nev,160),email:clean(a.email,240).toLowerCase(),telefon:clean(a.telefon,60)}).eq("id",args[0]);return{siker:true,uzenet:"Felhasználó módosítva."};}
  if(name==="adminFelhasznaloTorles"){await db.from("ugyfelek").delete().eq("id",args[0]);return{siker:true,uzenet:"Felhasználó törölve."};}
  return{siker:false,uzenet:"Ismeretlen művelet."};
}

Deno.serve(async req => {
  if(req.method==="OPTIONS")return new Response("ok",{headers:cors});
  try{
    const u=new URL(req.url), callback=clean(u.searchParams.get("callback"),120);
    let p:any={}; if(req.method==="GET")u.searchParams.forEach((v,k)=>p[k]=v);else p=await req.json();
    let name=p.muvelet||p.action||""; let args:any[]=[];
    if(name==="webHivas"){name=p.nev;try{args=JSON.parse(decodeURIComponent(p.args||"[]"))}catch{args=[]}}
    else if(p.args){try{args=Array.isArray(p.args)?p.args:JSON.parse(decodeURIComponent(p.args))}catch{args=[]}}
    const token=clean(p.sessionToken||p.token||req.headers.get("Authorization")?.replace(/^Bearer\s+/i,""),5000);
    let result:any;
    const adminNames=new Set(["onlineRendelesValtas","adminSoforListaLekerdezese","adminFuvarokLekerdezese","adminSoforHelyzetek","adminErtekelesLista","adminTiltolistaLekerdezese","adminFelhasznaloLista","adminSoforDolgozikValtas","adminSoforEmailMentese","adminSoforJarmuMentese","adminSoforLetrehozasa","adminSoforTorlese","adminFuvarMentese","adminFuvarTorlese","adminErtekelesAllapot","adminErtekelesTorles","adminUgyfelTiltasa","adminTiltoFeloldasa","adminFelhasznaloPont","adminFelhasznaloSzerkesztes","adminFelhasznaloTorles","adminNapiOsszesito","adminFuvarArchivum","adminFuvarVisszahelyezese"]);
    const driverNames=new Set(["soforSajatDolgozikAllapot","soforSajatDolgozikValtas","ujFuvarokLekerdezese","soforKezdoAdatok","fuvarElvallalasa","fuvarKesz","soforAppHelyzetFrissites","soforUgyfelJavaslatok","soforFuvarHozzaadas","soforRendelesMegkapva","soforKijelentkezes"]);
    const customerNames=new Set(["torzsProfilLekerdezese","torzsSajatFuvarok","torzsPontBevaltas","torzsKijelentkezes","confirmBooking"]);
    if(adminNames.has(name)||(name==="onlineRendelesAllapot"&&token))result=await adminAction(name,args,token);
    else if(driverNames.has(name))result=await driverAction(name,args,token);
    else if(customerNames.has(name)){const t=token||clean(args[0],5000);const customerArgs=(!token&&args.length&&args[0]===t)?args.slice(1):args;result=await customerAction(name,customerArgs,t);}
    else result=await publicAction(name,{...p,args},req.headers.get("origin")||"https://autoberlessoforrelkiskoros.hu");
    return out(result,callback);
  }catch(e){console.error(e);return out({siker:false,uzenet:"Szerverhiba."});}
});
