package org.drtvdark.watchdog;

import android.util.Base64;
import android.os.Build;
import org.json.JSONArray;
import org.json.JSONObject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.interfaces.RSAKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

/** Exact canonical signed metadata. Public key/config are embedded in the signed APK. */
public final class ManifestVerifier {
    private ManifestVerifier() {}
    public static final class Info {
        public final String spki, endpoint, website, homeActivity, certificate, originalPackage, applicationPackage, originalVersion, darkVersion;
        public final long sequence, originalCode;
        public final boolean diagnostics;
        public Info(JSONObject o) throws Exception {
            spki=o.getString("releaseSpki"); endpoint=https(o.getString("endpoint"));
            website=https(o.getString("website")); homeActivity=o.getString("homeActivity");
            certificate=hash(o.getString("commonCertificate")); sequence=number(o,"sequence");
            JSONObject original=o.getJSONObject("original");
            originalPackage=original.getString("package"); originalVersion=original.getString("versionName");
            originalCode=number(original,"versionCode"); diagnostics=o.optBoolean("diagnostics",false);
            applicationPackage=o.optString("applicationPackage",originalPackage);
            require(applicationPackage.matches("[A-Za-z0-9_.]{1,128}"),"installed application package");
            darkVersion=o.optString("darkVersion","development."+sequence);
            require(darkVersion.matches("[A-Za-z0-9.-]{1,64}"),"installed Dark version");
            require(sequence>=0 && originalCode>0 && spki.length()<2048,"config bounds");
        }
    }
    public static final class Candidate {
        public final long sequence, minimum, supportedOriginalCode, issuedAt, expiresAt;
        public final String website, darkVersion, originalVersion;
        public final Official official;
        public final boolean released, artifactsVerified, compatible, sameSigner;
        Candidate(JSONObject p, Info info) throws Exception {
            long schema=number(p,"schema");require(schema==3||schema==4||schema==5||schema==6,"schema");
            exact(p,schema==3?"artifactsVerified,commonCertificate,darkVersion,minInstalledSequence,originals,releaseDate,released,schema,sequence,website":schema==4?"artifactsVerified,commonCertificate,darkVersion,latestOfficial,minInstalledSequence,originals,releaseDate,released,schema,sequence,verification,website":schema==5?"artifactsVerified,commonCertificate,darkVersion,expiresAt,issuedAt,latestOfficial,minInstalledSequence,originals,releaseDate,released,schema,sequence,verification,website":"artifactsVerified,commonCertificate,darkVersion,expiresAt,issuedAt,latestOfficial,minInstalledSequence,originals,releaseDate,released,schema,sequence,upgrade,verification,website");
            issuedAt=schema>=5?Official.timestamp(p.getString("issuedAt")):0;
            // Schema6 retains its exact signed fields. Only the explicit empty string
            // means no expiry; missing/null/malformed dates still fail closed. Older
            // clients reject this value, rather than silently weakening their policy.
            boolean permanent=schema==6&&p.getString("expiresAt").isEmpty();
            expiresAt=permanent?0:schema>=5?Official.timestamp(p.getString("expiresAt")):0;
            require(schema<5||(issuedAt>0&&(permanent||(expiresAt>issuedAt&&expiresAt-issuedAt<=7*UpdatePolicy.DAY_MS))),"metadata validity bounds");
            sequence=number(p,"sequence"); minimum=number(p,"minInstalledSequence");
            require(sequence>=0 && minimum>=0 && minimum<=sequence,"sequence bounds");
            darkVersion=p.getString("darkVersion");require(darkVersion.matches("[A-Za-z0-9.-]{1,64}"),"dark version");
            require(p.getString("releaseDate").matches("[0-9]{4}-[0-9]{2}-[0-9]{2}"),"release date");
            released=bool(p,"released");
            boolean proofs=false;
            if(schema>=4){JSONObject v=p.getJSONObject("verification");exact(v,"browserPatchSha256,independentlyVerified,publicSigningSha256,releaseArtifactsSha256,sequence");require(number(v,"sequence")==sequence,"verification sequence mismatch");hash(v.getString("browserPatchSha256"));hash(v.getString("publicSigningSha256"));hash(v.getString("releaseArtifactsSha256"));proofs=bool(v,"independentlyVerified");}
            // Legacy schema remains readable for historical fixtures, but cannot announce in B5.
            artifactsVerified=bool(p,"artifactsVerified")&&proofs;
            official=schema>=4?Official.read(p.optJSONObject("latestOfficial"),schema):Official.unknown();
            sameSigner=hash(p.getString("commonCertificate")).equals(info.certificate);
            website=https(p.getString("website")); require(website.equals(info.website),"website pin");
            JSONArray originals=p.getJSONArray("originals"); require(originals.length()>0&&originals.length()<=8,"originals bounds");
            String matchingVersion="";long supported=0;
            for(int i=0;i<originals.length();i++){
                JSONObject original=originals.getJSONObject(i); exact(original,"package,variants,versionCode,versionName");
                String pkg=original.getString("package"),version=original.getString("versionName");long code=number(original,"versionCode");if(i==0)matchingVersion=version;
                require(pkg.matches("[A-Za-z0-9_.]{1,128}")&&version.matches("[A-Za-z0-9.-]{1,64}")&&code>0,"original identity");
                if(pkg.equals(info.originalPackage))supported=Math.max(supported,code);
                JSONArray variants=original.getJSONArray("variants");require(variants.length()>0&&variants.length()<=8,"variant bounds");
                for(int j=0;j<variants.length();j++){
                    JSONObject v=variants.getJSONObject(j);exact(v,"baseSha256,id,splitSha256");
                    require(v.getString("id").matches("[A-Za-z0-9.-]{1,64}"),"variant id");hash(v.getString("baseSha256"));hash(v.getString("splitSha256"));
                }
            }
            // originals describes exact browser inputs, never installed upgrade origins.
            // Historical envelopes remain readable but cannot establish current/upgrade status.
            compatible=schema==6&&upgrade(p,info,originals);originalVersion=matchingVersion;supportedOriginalCode=supported;
        }
        // Valid signed time policy is distinct from a recent successful network check.
        public boolean metadataFresh(long now){return issuedAt>0&&now>0&&now>=issuedAt-5*60*1000L&&(expiresAt==0||now<expiresAt);}
    }
    private static boolean upgrade(JSONObject p,Info info,JSONArray originals)throws Exception {
        JSONObject u=p.getJSONObject("upgrade");exact(u,u.has("sourcePackage")?"from,package,releaseArtifactsSha256,sequence,sourcePackage,target":"from,package,releaseArtifactsSha256,sequence,target");
        require(number(u,"sequence")==number(p,"sequence"),"upgrade sequence binding");
        require(hash(u.getString("releaseArtifactsSha256")).equals(p.getJSONObject("verification").getString("releaseArtifactsSha256")),"upgrade artifact binding");
        String pkg=u.getString("package");require(pkg.matches("[A-Za-z0-9_.]{1,128}"),"upgrade package");
        String sourcePackage=u.has("sourcePackage")?u.getString("sourcePackage"):pkg;
        require(sourcePackage.equals(info.originalPackage),"upgrade original-source package");
        JSONObject t=u.getJSONObject("target");exact(t,"baseSha256,commonCertificate,darkVersion,minSdk,sourceCatalogSha256,splitSha256,versionCode,versionName");
        hash(t.getString("baseSha256"));hash(t.getString("splitSha256"));
        require(hash(t.getString("commonCertificate")).equals(p.getString("commonCertificate")),"target signer binding");
        require(t.getString("darkVersion").equals(p.getString("darkVersion")),"target Dark binding");
        require(hash(t.getString("sourceCatalogSha256")).equals(digest(canonical(originals))),"target source catalog binding");
        long code=number(t,"versionCode"),sdk=number(t,"minSdk");String version=t.getString("versionName");
        require(code>0&&code<=Integer.MAX_VALUE&&sdk>=24&&sdk<=Integer.MAX_VALUE&&version.matches("[A-Za-z0-9.-]{1,64}"),"target Android bounds");
        // Original-source admission and installed Dark identity are independent.
        // Their signed package mapping must be explicit when the identities differ.
        for(int n=0;n<originals.length();n++){
            JSONObject o=originals.getJSONObject(n);
            require(o.getString("package").equals(sourcePackage)&&number(o,"versionCode")==code&&o.getString("versionName").equals(version),"target/source identity");
        }
        JSONArray from=u.getJSONArray("from");require(from.length()<=32,"upgrade origin bounds");
        boolean authorized=false;ArrayList<String> identities=new ArrayList<>();
        for(int n=0;n<from.length();n++){
            JSONObject f=from.getJSONObject(n);exact(f,"darkVersion,originalVersionCode,originalVersionName,sequence");
            long seq=number(f,"sequence"),original=number(f,"originalVersionCode");
            String dark=f.getString("darkVersion"),name=f.getString("originalVersionName");
            require(seq>=number(p,"minInstalledSequence")&&seq<number(p,"sequence")&&original>0&&original<=Integer.MAX_VALUE&&dark.matches("[A-Za-z0-9.-]{1,64}")&&name.matches("[A-Za-z0-9.-]{1,64}"),"upgrade origin identity");
            String identity=canonical(f);require(!identities.contains(identity),"duplicate upgrade origin");identities.add(identity);
            if(seq==info.sequence&&original==info.originalCode&&dark.equals(info.darkVersion)&&name.equals(info.originalVersion))authorized=true;
        }
        boolean installedTarget=info.sequence==number(p,"sequence")&&info.darkVersion.equals(t.getString("darkVersion"))&&info.originalCode==code&&info.originalVersion.equals(version);
        return pkg.equals(info.applicationPackage)&&code>=info.originalCode&&Build.VERSION.SDK_INT>=sdk&&(authorized||installedTarget);
    }
    private static String digest(String text)throws Exception {
        byte[] bytes=MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));StringBuilder b=new StringBuilder();for(byte v:bytes)b.append(String.format(java.util.Locale.ROOT,"%02x",v&255));return b.toString();
    }
    public static final class Official {
        public final String version,date,source,status,limitations; public final long verifiedAt,versionCode;
        private Official(String version,String date,String source,long at,long code,String status,String limitations){this.version=version;this.date=date;this.source=source;this.verifiedAt=at;this.versionCode=code;this.status=status;this.limitations=limitations;}
        static Official unknown(){return new Official("","","",0,0,"unknown","");}
        static Official read(JSONObject o,long schema){try{
            if(schema>=5){
                exact(o,"evidence,limitations,observedAt,package,status,verifiedAt,versionCode,versionName");
                require(o.getString("package").equals("dk.dr.tvplayer"),"TV package");
                String state=o.getString("status");require(state.equals("unknown")||state.equals("candidate")||state.equals("verified"),"official status");
                String limits=o.getString("limitations");require(limits.length()>0&&limits.length()<=256,"applicability");
                if(state.equals("unknown"))return unknown();
                String version=o.getString("versionName"),observed=o.getString("observedAt"),verified=o.getString("verifiedAt");long code=number(o,"versionCode");
                require(version.matches("[A-Za-z0-9.-]{1,64}")&&code>0,"official version");
                long observation=timestamp(observed);JSONArray evidence=o.getJSONArray("evidence");require(evidence.length()>0&&evidence.length()<=8,"official evidence");String source="";
                for(int n=0;n<evidence.length();n++){JSONObject e=evidence.getJSONObject(n);exact(e,"sha256,sourceId,url");hash(e.getString("sha256"));String url=e.getString("url");URI u=new URI(url);require(url.length()<=512&&"https".equals(u.getScheme())&&u.getHost()!=null&&u.getUserInfo()==null&&u.getFragment()==null,"evidence URL");String id=e.getString("sourceId");require(id.matches("[A-Za-z0-9._/-]{1,128}"),"evidence ID");if(n==0)source=id;}
                long at=state.equals("verified")?timestamp(verified):0;require(at==0||at>=observation,"verification time");
                return new Official(version,state.equals("verified")?verified.substring(0,10):observed.substring(0,10),source,at,code,state,limits);
            }
            exact(o,"package,sourceId,sourceUrl,verified,verifiedOn,versionCode,versionName");
            require(bool(o,"verified")&&o.getString("package").equals("dk.dr.tvplayer"),"verified TV identity");
            String version=o.getString("versionName"),date=o.getString("verifiedOn"),source=o.getString("sourceId");
            require(version.matches("[A-Za-z0-9.-]{1,64}")&&number(o,"versionCode")>0&&source.matches("[A-Za-z0-9._/-]{1,128}"),"official identity/evidence");
            https(o.getString("sourceUrl"));require(date.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}"),"official date");
            java.text.SimpleDateFormat format=new java.text.SimpleDateFormat("yyyy-MM-dd",java.util.Locale.ROOT);format.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));format.setLenient(false);
            long at=format.parse(date).getTime();return new Official(version,date,source,at,number(o,"versionCode"),"verified","Begrænset observation; udrulning kan variere.");
        }catch(Exception ignored){return unknown();}}
        private static long timestamp(String s)throws Exception {require(s.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"),"UTC timestamp");java.text.SimpleDateFormat f=new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'",java.util.Locale.ROOT);f.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));f.setLenient(false);return f.parse(s).getTime();}
    }
    public static boolean usableWebsite(String s){try{https(s);String host=new URI(s).getHost();return host!=null&&!host.equals("invalid")&&!host.endsWith(".invalid");}catch(Exception ignored){return false;}}
    public static Candidate verify(String text, Info info) throws Exception {
        require(text.getBytes(StandardCharsets.UTF_8).length<=32768,"manifest size");guardJson(text);JSONObject outer=new JSONObject(text);exact(outer,"payload,signature");
        String payload=outer.getString("payload"),signature=outer.getString("signature");
        require(payload.getBytes(StandardCharsets.UTF_8).length<=24576&&signature.matches("[A-Za-z0-9+/]{1,1024}={0,2}"),"envelope bounds");
        guardJson(payload);JSONObject parsed=new JSONObject(payload);require(canonical(parsed).equals(payload),"canonical/duplicate fields");
        PublicKey key=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(info.spki,Base64.NO_WRAP)));
        require(key instanceof RSAKey&&((RSAKey)key).getModulus().bitLength()>=3072,"release key strength");
        Signature verifier=Signature.getInstance("SHA256withRSA");verifier.initVerify(key);verifier.update(payload.getBytes(StandardCharsets.UTF_8));
        require(verifier.verify(Base64.decode(signature,Base64.NO_WRAP)),"release signature");
        return new Candidate(parsed,info);
    }
    static void require(boolean ok,String message) throws Exception {if(!ok)throw new Exception(message);}
    static long number(JSONObject o,String key) throws Exception {Object v=o.get(key);require(v instanceof Integer||v instanceof Long,"integer required");long n=((Number)v).longValue();require(n>=-9007199254740991L&&n<=9007199254740991L,"safe integer");return n;}
    static boolean bool(JSONObject o,String key) throws Exception {Object v=o.get(key);require(v instanceof Boolean,"boolean required");return (Boolean)v;}
    static String hash(String s) throws Exception {require(s.matches("[0-9a-f]{64}"),"SHA256 encoding");return s;}
    static String https(String s) throws Exception {URI u=new URI(s);require(s.length()<=256&&s.matches("https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./-]*")&&u.getUserInfo()==null&&u.getFragment()==null&&u.getQuery()==null,"HTTPS URL");return s;}
    static void exact(JSONObject o,String keys) throws Exception {ArrayList<String> actual=new ArrayList<>();Iterator<String> it=o.keys();while(it.hasNext())actual.add(it.next());Collections.sort(actual);StringBuilder b=new StringBuilder();for(String k:actual){if(b.length()>0)b.append(',');b.append(k);}require(b.toString().equals(keys),"unexpected fields");}
    static void guardJson(String s) throws Exception {int depth=0;boolean quoted=false,escape=false;for(int i=0;i<s.length();i++){char c=s.charAt(i);if(quoted){if(escape)escape=false;else if(c=='\\')escape=true;else if(c=='"')quoted=false;}else if(c=='"')quoted=true;else if(c=='{'||c=='['){depth++;require(depth<=12,"JSON nesting limit");}else if(c=='}'||c==']'){depth--;require(depth>=0,"JSON nesting");}}require(!quoted&&depth==0,"JSON completeness");}
    static String quote(String s) throws Exception {
        // Release fields are ASCII by schema. Canonical envelope parsing also rejects
        // ambiguous escapes and UTF-16 surrogate spellings before trusting a release.
        StringBuilder b=new StringBuilder("\"");for(int i=0;i<s.length();i++){char c=s.charAt(i);require(c>=32&&c<=126,"ASCII manifest strings");if(c=='"'||c=='\\')b.append('\\');b.append(c);}return b.append('"').toString();
    }
    static String canonical(Object value) throws Exception {
        if(value==JSONObject.NULL)return "null";if(value instanceof String)return quote((String)value);
        if(value instanceof Boolean)return value.toString();if(value instanceof Integer||value instanceof Long)return value.toString();
        if(value instanceof JSONArray){JSONArray a=(JSONArray)value;StringBuilder b=new StringBuilder("[");for(int i=0;i<a.length();i++){if(i>0)b.append(',');b.append(canonical(a.get(i)));}return b.append(']').toString();}
        require(value instanceof JSONObject,"canonical type");JSONObject o=(JSONObject)value;ArrayList<String> keys=new ArrayList<>();Iterator<String> it=o.keys();while(it.hasNext())keys.add(it.next());Collections.sort(keys);StringBuilder b=new StringBuilder("{");for(String k:keys){if(b.length()>1)b.append(',');b.append(quote(k)).append(':').append(canonical(o.get(k)));}return b.append('}').toString();
    }
}
