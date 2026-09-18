import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const url = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
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
async function issueSession(szerepkor:string,felhasznalo:string,soforId:string|null){const token=randomHex(32);await db.from("login_sessions").insert({token_hash:await sha256(token),szerepkor,felhasznalo,sofor_id:soforId,lejar:new Date(Date.now()+30*24*3600*1000).toISOString()});return token}
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
  if (!data || (wanted && data.szerepkor !== wanted)) return null;
  return { ...data, user: ud.user };
}
async function tripByRow(row: unknown, active = false) {
  if (typeof row === "string" && /^[0-9a-f-]{32,36}$/i.test(row)) return row;
  const n = Math.max(1, Number(row) || 1);
  let q:any = db.from("fuvarok").select("id");
  if (active) q=q.in("statusz",["Új rendelés","Elvállalva"]);
  const { data } = await q.order("datum").order("ido", { nullsFirst: true }).order("letrehozva").range(n - 1, n - 1).maybeSingle();
  return data?.id || null;
}
async function sendOtp(email: string, redirectTo: string, meta: Record<string,string> = {}) {
  const auth = createClient(url, anonKey, { auth: { persistSession: false } });
  return await auth.auth.signInWithOtp({ email, options: { emailRedirectTo: redirectTo, data: meta, shouldCreateUser: true } });
}

async function publicAction(name: string, p: any, origin: string) {
  if(name==="torzsFelhasznaloBelepes"){
    const az=clean(p.args?.[0],240).toLowerCase(),clientHash=clean(p.args?.[1],128).toLowerCase();
    if(!az||!/^[a-f0-9]{64}$/.test(clientHash))return{siker:false,uzenet:"Hibás email/felhasználónév vagy jelszó."};
    const legacy=await legacyWebCall("torzsFelhasznaloBelepes",[az,clientHash]);
    if(!legacy?.siker||!legacy.token)return{siker:false,uzenet:legacy?.uzenet||"Hibás email/felhasználónév vagy jelszó."};
    const profil=await legacyWebCall("torzsProfilLekerdezese",[legacy.token]),u=profil?.profil;
    if(!u?.email)return{siker:false,uzenet:"A régi fiók adatait nem sikerült betölteni."};
    const email=clean(u.email,240).toLowerCase();
    await db.from("ugyfelek").upsert({legacy_id:clean(u.id,160)||null,nev:clean(u.nev,160),telefon:clean(u.telefon,60),email,pont:Number(u.pont)||0,teljesitett_fuvar:Number(u.teljesitettFuvar)||0,szint:clean(u.szint,40)||"Bronz",frissitve:new Date().toISOString()},{onConflict:"email"});
    return{siker:true,token:await issueSession("ugyfel",email,null)};
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
    const alap=`format=json&countrycodes=hu&limit=15&addressdetails=1&accept-language=hu&q=${encodeURIComponent(q)}`;
    let r = await fetch(`https://nominatim.openstreetmap.org/search?${alap}&viewbox=18.8,46.95,19.8,46.30&bounded=1`, { headers: { "User-Agent": "AutoberlesSoforrel/1.0" } });
    let a = r.ok ? await r.json() : [];
    if(!Array.isArray(a)||!a.length){r=await fetch(`https://nominatim.openstreetmap.org/search?${alap}`,{headers:{"User-Agent":"AutoberlesSoforrel/1.0"}});a=r.ok?await r.json():[]}
    const tav=(x:any)=>{const lat=Number(x.lat),lon=Number(x.lon),dLat=(lat-46.6214)*Math.PI/180,dLon=(lon-19.2850)*Math.PI/180,p1=46.6214*Math.PI/180,p2=lat*Math.PI/180,h=Math.sin(dLat/2)**2+Math.cos(p1)*Math.cos(p2)*Math.sin(dLon/2)**2;return 6371*2*Math.atan2(Math.sqrt(h),Math.sqrt(1-h))};
    return { lista: (Array.isArray(a) ? a : []).sort((x:any,y:any)=>tav(x)-tav(y)).slice(0,6).map((x:any) => ({ cim: x.display_name })) };
  }
  if (name === "foglalasKuldes") {
    let a:any = {}; try { a = JSON.parse(decodeURIComponent(String(p.adat || "{}"))); } catch {}
    const email = clean(a.email,240).toLowerCase(), telefon = clean(a.telefon,60);
    if (!email.includes("@") || clean(a.nev,160).length < 2 || clean(a.indulas).length < 3 || clean(a.cel).length < 3) return { siker:false,uzenet:"Tölts ki minden kötelező mezőt!" };
    const { data: blocked } = await db.from("tiltolista").select("id").or(`and(tipus.eq.email,ertek.eq.${email}),and(tipus.eq.telefon,ertek.eq.${telefon})`).limit(1);
    if (blocked?.length) return { siker:false,uzenet:"Erről az elérhetőségről nem adható le rendelés." };
    const azonosito = id(), planned = a.rendelesTipus === "idopont";
    const datum = planned && a.datum ? a.datum : new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date());
    const { error } = await db.from("fuvarok").insert({ azonosito, nev:clean(a.nev,160), telefon, email, indulas:clean(a.indulas), cel:clean(a.cel), datum, ido:planned ? clean(a.ido,8) || null : null, utasok:Math.max(1,Math.min(9,Number(a.utasok)||1)), megjegyzes:clean(a.megjegyzes,2000), statusz:"Új rendelés" });
    if (error) return { siker:false,uzenet:"Nem sikerült elmenteni a rendelést." };
    return { siker:true,foglalasiAzonosito:azonosito,uzenet:"A rendelés sikeresen elküldve a sofőröknek." };
  }
  if (name === "utasAppKovetes") {
    const az = clean(p.id || p.azonosito || p.args?.[0],120);
    const { data } = await db.from("fuvarok").select("*").eq("azonosito",az).maybeSingle();
    if (!data) return { siker:false,uzenet:"A rendelés nem található." };
    return { siker:true,...normalizeTrip(data),sofor:data.sofor_nev,menetido:data.menetido_perc,erkezes:data.varhato_erkezes };
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
    return error||!data?{siker:false,uzenet:"A rendelés nem található, vagy már megerősítetted."}:{siker:true,azonosito:az};
  }
  return {siker:false,uzenet:"Ismeretlen művelet."};
}

async function driverAction(name:string,args:any[],token:string) {
  const r=await role(token,"sofor"); if(!r) return {siker:false,uzenet:"A munkamenet lejárt."};
  const {data:s}=await db.from("soforok").select("*").eq("id",r.sofor_id).single();
  if(name==="soforSajatDolgozikAllapot") return {siker:true,dolgozik:!!s.dolgozik};
  if(name==="soforSajatDolgozikValtas"){await db.from("soforok").update({dolgozik:!s.dolgozik,frissitve:new Date().toISOString()}).eq("id",s.id);return{siker:true,dolgozik:!s.dolgozik};}
  if(name==="ujFuvarokLekerdezese"||name==="soforKezdoAdatok"){
    const {data}=await db.from("fuvarok").select("*").in("statusz",["Új rendelés","Elvállalva"]).gte("datum",new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(new Date())).order("datum").order("ido",{nullsFirst:true});
    const now=new Date(), today=new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Budapest"}).format(now), cutoff=now.getTime()-2*60*60*1000;
    const aktiv=(data||[]).filter((x:any)=>{if(x.datum>today)return true;if(x.datum<today)return false;if(x.ido){const planned=new Date(`${x.datum}T${String(x.ido).slice(0,8)}+02:00`).getTime();return planned>=now.getTime()-30*60*1000}return new Date(x.letrehozva).getTime()>=cutoff});
    const lista=aktiv.filter((x:any)=>x.statusz==="Új rendelés"||x.sofor_id===s.id).map(normalizeTrip); return name==="soforKezdoAdatok"?{siker:true,nev:s.nev,dolgozik:!!s.dolgozik,munka:{siker:true,dolgozik:!!s.dolgozik},fuvarok:lista}:{siker:true,lista};
  }
  if(name==="fuvarElvallalasa"||name==="fuvarKesz"){
    const fid=await tripByRow(args[0],true); if(!fid)return{siker:false,uzenet:"A fuvar nem található."};
    if(name==="fuvarElvallalasa"){
      const {data,error}=await db.from("fuvarok").update({statusz:"Elvállalva",sofor_id:s.id,sofor_nev:s.nev}).eq("id",fid).eq("statusz","Új rendelés").select("azonosito").maybeSingle();
      return error||!data?{siker:false,uzenet:"Ezt a fuvart már elvállalták."}:{siker:true};
    }
    await db.from("fuvarok").update({statusz:"Kész"}).eq("id",fid).eq("sofor_id",s.id); return{siker:true};
  }
  if(name==="soforAppHelyzetFrissites"){
    const [az,lat,lng]=args; const {data:f}=await db.from("fuvarok").select("id").eq("azonosito",clean(az,120)).eq("sofor_id",s.id).eq("statusz","Elvállalva").maybeSingle();
    if(!f)return{siker:false}; await db.from("fuvar_helyzet").upsert({fuvar_id:f.id,lat:Number(lat),lng:Number(lng),frissitve:new Date().toISOString()});return{siker:true};
  }
  if(name==="soforUgyfelJavaslatok") {const q=clean(args[0],100);const{data}=await db.from("ugyfelek").select("nev,telefon,email").or(`nev.ilike.%${q}%,telefon.ilike.%${q}%`).limit(8);return{siker:true,lista:data||[]};}
  if(name==="soforFuvarHozzaadas") {const a=args[0]||{}, az=id();const{error}=await db.from("fuvarok").insert({azonosito:az,nev:clean(a.nev,160),telefon:clean(a.telefon,60),email:clean(a.email,240)||null,indulas:clean(a.indulas),cel:clean(a.cel),datum:a.datum,ido:a.ido||null,utasok:Number(a.utasok)||1,megjegyzes:clean(a.megjegyzes,2000),statusz:"Új rendelés"});return error?{siker:false,uzenet:"Nem sikerült menteni."}:{siker:true,uzenet:"Fuvar elmentve."};}
  if(name==="soforKijelentkezes"){await db.from("login_sessions").delete().eq("token_hash",await sha256(token));return{siker:true};}
  return{siker:false,uzenet:"Ismeretlen művelet."};
}

async function adminAction(name:string,args:any[],token:string){
  const r=await role(token,"admin");if(!r)return{siker:false,uzenet:"A munkamenet lejárt."};
  if(name==="onlineRendelesAllapot"){const{data}=await db.from("app_beallitasok").select("ertek").eq("kulcs","online_rendeles").single();return{online:data.ertek===true};}
  if(name==="onlineRendelesValtas"){const{data}=await db.from("app_beallitasok").select("ertek").eq("kulcs","online_rendeles").single();await db.from("app_beallitasok").update({ertek:!(data.ertek===true),frissitve:new Date().toISOString()}).eq("kulcs","online_rendeles");return{siker:true};}
  if(name==="adminSoforListaLekerdezese"){const{data}=await db.from("soforok").select("*").eq("aktiv",true).order("nev");return(data||[]).map((x:any)=>({felhasznalo:x.felhasznalo,nev:x.nev,email:x.email,dolgozik:x.dolgozik,autoTipus:x.auto_tipus,autoSzin:x.auto_szin,rendszam:x.rendszam}));}
  if(name==="adminFuvarokLekerdezese"){const{data}=await db.from("fuvarok").select("*").order("datum").order("ido",{nullsFirst:true});return(data||[]).map(normalizeTrip);}
  if(name==="adminErtekelesLista"){const{data}=await db.from("ertekelesek").select("*").order("id",{ascending:false});return(data||[]).map((x:any)=>({...x,sor:x.legacy_sor||x.id}));}
  if(name==="adminTiltolistaLekerdezese"){const{data}=await db.from("tiltolista").select("*").order("letrehozva",{ascending:false});return data||[];}
  if(name==="adminFelhasznaloLista"){const{data}=await db.from("ugyfelek").select("*").order("nev");return{siker:true,lista:(data||[]).map((x:any)=>({...x,teljesitettFuvar:x.teljesitett_fuvar}))};}
  if(name==="adminSoforDolgozikValtas"){const u=clean(args[0],120),{data}=await db.from("soforok").select("dolgozik").eq("felhasznalo",u).single();await db.from("soforok").update({dolgozik:!data.dolgozik}).eq("felhasznalo",u);return{siker:true};}
  if(name==="adminSoforEmailMentese"){await db.from("soforok").update({email:clean(args[1],240).toLowerCase()}).eq("felhasznalo",clean(args[0],120));return{siker:true,uzenet:"Email elmentve."};}
  if(name==="adminSoforJarmuMentese"){await db.from("soforok").update({auto_tipus:clean(args[1],160),auto_szin:clean(args[2],80),rendszam:clean(args[3],40)}).eq("felhasznalo",clean(args[0],120));return{siker:true,uzenet:"Jármű elmentve."};}
  if(name==="adminSoforLetrehozasa"){const[u,pw,email,auto,szin,rsz]=[clean(args[1],120).toLowerCase(),clean(args[2],128),args[3],args[4],args[5],args[6]];const{data:s,error}=await db.from("soforok").insert({nev:clean(args[0],160),felhasznalo:u,email:clean(email,240).toLowerCase(),auto_tipus:clean(auto,160),auto_szin:clean(szin,80),rendszam:clean(rsz,40)}).select("id").single();if(!error&&/^[a-f0-9]{64}$/.test(pw))await saveCredential("sofor",u,pw,s.id);return error?{siker:false,uzenet:error.message}:{siker:true,uzenet:"Sofőr hozzáadva."};}
  if(name==="adminSoforTorlese"){await db.from("soforok").update({aktiv:false,dolgozik:false}).eq("felhasznalo",clean(args[0],120));return{siker:true,uzenet:"Sofőr törölve."};}
  if(name==="adminFuvarMentese"){const a=args[0]||{},fid=await tripByRow(a.sor);if(!fid)return{siker:false,uzenet:"Nincs ilyen fuvar."};await db.from("fuvarok").update({nev:clean(a.nev,160),telefon:clean(a.telefon,60),email:clean(a.email,240)||null,indulas:clean(a.indulas),cel:clean(a.cel),datum:a.datum,ido:a.ido||null,utasok:Number(a.utasok)||1,statusz:clean(a.statusz,80),sofor_nev:clean(a.sofor,160)||null,megjegyzes:clean(a.megjegyzes,2000)}).eq("id",fid);return{siker:true,uzenet:"Fuvar módosítva."};}
  if(name==="adminFuvarTorlese"){const fid=await tripByRow(args[0]);if(fid)await db.from("fuvarok").delete().eq("id",fid);return{siker:true};}
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
    const adminNames=new Set(["onlineRendelesValtas","adminSoforListaLekerdezese","adminFuvarokLekerdezese","adminErtekelesLista","adminTiltolistaLekerdezese","adminFelhasznaloLista","adminSoforDolgozikValtas","adminSoforEmailMentese","adminSoforJarmuMentese","adminSoforLetrehozasa","adminSoforTorlese","adminFuvarMentese","adminFuvarTorlese","adminErtekelesAllapot","adminErtekelesTorles","adminUgyfelTiltasa","adminTiltoFeloldasa","adminFelhasznaloPont","adminFelhasznaloSzerkesztes","adminFelhasznaloTorles"]);
    const driverNames=new Set(["soforSajatDolgozikAllapot","soforSajatDolgozikValtas","ujFuvarokLekerdezese","soforKezdoAdatok","fuvarElvallalasa","fuvarKesz","soforAppHelyzetFrissites","soforUgyfelJavaslatok","soforFuvarHozzaadas","soforKijelentkezes"]);
    const customerNames=new Set(["torzsProfilLekerdezese","torzsSajatFuvarok","torzsPontBevaltas","torzsKijelentkezes","confirmBooking"]);
    if(adminNames.has(name)||(name==="onlineRendelesAllapot"&&token))result=await adminAction(name,args,token);
    else if(driverNames.has(name))result=await driverAction(name,args,token);
    else if(customerNames.has(name)){const t=token||clean(args[0],5000);result=await customerAction(name,args,t);}
    else result=await publicAction(name,{...p,args},req.headers.get("origin")||"https://autoberlessoforrelkiskoros.hu");
    return out(result,callback);
  }catch(e){console.error(e);return out({siker:false,uzenet:"Szerverhiba."});}
});
