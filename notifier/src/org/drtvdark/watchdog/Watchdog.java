package org.drtvdark.watchdog;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.os.*;
import android.util.Log;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.lang.ref.WeakReference;
import java.net.*;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/** Foreground lifecycle coordinator. The provider only registers this callback. */
final class Watchdog implements Application.ActivityLifecycleCallbacks {
    static Watchdog instance;
    private final Application app;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final AtomicBoolean busy=new AtomicBoolean();
    private volatile ManifestVerifier.Info info;
    private volatile ManifestVerifier.Candidate latest,pending;
    private volatile String status="Ingen kontrol endnu.";
    private volatile long checkedAt;
    private volatile boolean checkSucceeded;
    private UpdatePolicy.Clock reminderClock=System::currentTimeMillis;
    private WeakReference<Activity> foreground=new WeakReference<>(null);
    private WeakReference<UpdateActivity> screen=new WeakReference<>(null);
    private WeakReference<View> returnFocus=new WeakReference<>(null);
    private View root;
    private ViewTreeObserver.OnGlobalLayoutListener layout;
    private ViewTreeObserver.OnGlobalFocusChangeListener focus;
    private ViewTreeObserver.OnScrollChangedListener scroll;
    private ViewTreeObserver.OnWindowFocusChangeListener window;
    private Runnable readiness;
    private long generation,readyAfter;
    private boolean opening;
    private boolean ignoreConfirmationPending;
    private View ignoreConfirmation;
    private Runnable dismissConfirmation;
    Watchdog(Application app){this.app=app;instance=this;}
    private SharedPreferences prefs(){return app.getSharedPreferences("drtv_dark_manager_v5",Context.MODE_PRIVATE);}
    ManifestVerifier.Info info(){return info;}
    ManifestVerifier.Candidate latest(){return latest;}
    String status(){return status;}
    boolean fresh(){long now=System.currentTimeMillis();return checkSucceeded&&checkedAt>0&&now>=checkedAt&&now-checkedAt<UpdatePolicy.DAY_MS&&latest!=null&&latest.metadataFresh(now);}
    boolean trusted(){ManifestVerifier.Candidate c=latest;ManifestVerifier.Info i=info;return c!=null&&i!=null&&c.released&&c.artifactsVerified&&c.sameSigner&&c.compatible&&i.sequence>=c.minimum&&c.sequence>=prefs().getLong("highestSeen",0);}
    String primaryStatus(){ManifestVerifier.Candidate c=latest;ManifestVerifier.Info i=info;return UpdatePolicy.darkStatus(fresh(),trusted(),available(c),i==null?0:i.sequence,c==null?0:c.sequence,c!=null&&i!=null&&c.darkVersion.equals(i.darkVersion));}
    boolean available(ManifestVerifier.Candidate c){ManifestVerifier.Info i=info;return c!=null&&i!=null&&!c.darkVersion.equals(i.darkVersion)&&UpdatePolicy.available(c.released,c.artifactsVerified,c.compatible,c.sameSigner,c.sequence,i.sequence,c.minimum,prefs().getLong("highestSeen",0),0);}
    boolean canUpdate(){return fresh()&&available(latest)&&ManifestVerifier.usableWebsite(latest.website);}
    void attach(UpdateActivity a){screen=new WeakReference<>(a);refresh();}
    void detach(UpdateActivity a){if(screen.get()==a)screen.clear();}
    private void refresh(){main.post(()->{UpdateActivity a=screen.get();if(a!=null&&!a.isFinishing())a.refresh();});}
    private void event(String s){ManifestVerifier.Info i=info;if(i!=null&&i.diagnostics)Log.i("B5_MANAGER",s);}
    private static String limited(InputStream in,int limit,long deadline)throws Exception {
        try(InputStream stream=in;ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[2048];int n;
            while(true){if(SystemClock.elapsedRealtime()>deadline)throw new IOException("deadline");n=stream.read(buffer);if(SystemClock.elapsedRealtime()>deadline)throw new IOException("deadline");if(n<0)break;if(out.size()+n>limit)throw new IOException("size");out.write(buffer,0,n);}
            return out.toString("UTF-8");
        }
    }
    private String certificate()throws Exception {
        PackageInfo p=app.getPackageManager().getPackageInfo(app.getPackageName(),Build.VERSION.SDK_INT>=28?PackageManager.GET_SIGNING_CERTIFICATES:PackageManager.GET_SIGNATURES);
        android.content.pm.Signature[] signatures=Build.VERSION.SDK_INT>=28?p.signingInfo.getApkContentsSigners():p.signatures;
        if(signatures==null||signatures.length!=1)throw new Exception("one signer");
        byte[] bytes=MessageDigest.getInstance("SHA-256").digest(signatures[0].toByteArray());StringBuilder b=new StringBuilder();for(byte v:bytes)b.append(String.format(java.util.Locale.ROOT,"%02x",v&255));return b.toString();
    }
    private void initialize()throws Exception {
        if(info!=null)return;
        ManifestVerifier.Info i=new ManifestVerifier.Info(new JSONObject(limited(app.getAssets().open("drtv-dark-release.json"),8192,Long.MAX_VALUE)));
        if(!certificate().equals(i.certificate))throw new Exception("installed signer");
        PackageInfo installed=app.getPackageManager().getPackageInfo(app.getPackageName(),0);
        if(!app.getPackageName().equals(i.applicationPackage)||installed.versionCode!=i.originalCode||!i.originalVersion.equals(installed.versionName))throw new Exception("installed identity");
        // Warm disk preferences on this worker. Rebase corrupt/future times once.
        SharedPreferences p=prefs();long now=System.currentTimeMillis();SharedPreferences.Editor edit=p.edit();
        for(String key:new String[]{"lastAttempt","lastManual","ignoredAt","presentedAt"}){
            long at=p.getLong(key,0);boolean required=(key.equals("ignoredAt")&&p.getLong("ignoredSequence",0)>0)||(key.equals("presentedAt")&&p.getLong("presentedSequence",0)>0);
            if(at<0||at>now||(required&&at==0))edit.putLong(key,now);
        }
        edit.putLong("highestSeen",Math.max(i.sequence,p.getLong("highestSeen",0)));
        if(!edit.commit())throw new IOException("preferences");info=i;
        String cached=p.getString("verifiedEnvelope","");
        if(!cached.isEmpty())try{ManifestVerifier.Candidate c=ManifestVerifier.verify(cached,i);if(c.sequence>=p.getLong("highestSeen",0))latest=c;}catch(Exception ignored){}
        refresh();
    }
    void check(boolean manual){
        if(!busy.compareAndSet(false,true)){if(manual){status="Søger allerede…";refresh();}return;}
        Thread worker=new Thread(()->{
            HttpURLConnection connection=null;java.util.Timer timer=null;
            try{
                initialize();SharedPreferences p=prefs();long now=System.currentTimeMillis();
                if(manual){long last=p.getLong("lastManual",0);if(last!=0&&(now<last||now-last<5000)){status="Vent et øjeblik før næste kontrol.";return;}}
                else if(!UpdatePolicy.due(now,p.getLong("lastAttempt",0))){event("RATE_LIMITED");return;}
                pending=null;
                checkSucceeded=false;
                SharedPreferences.Editor edit=p.edit().putLong("lastAttempt",now);if(manual)edit.putLong("lastManual",now);if(!edit.commit())throw new IOException("preferences");
                status="Søger efter opdateringer…";refresh();event(manual?"MANUAL_CHECK_STARTED":"CHECK_STARTED");
                long begin=SystemClock.elapsedRealtime();
                connection=(HttpURLConnection)new URL(info.endpoint).openConnection();connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(1500);connection.setReadTimeout(1500);connection.setUseCaches(false);connection.setRequestProperty("Accept","application/json");connection.setRequestProperty("Cache-Control","no-cache, no-store");
                final HttpURLConnection guarded=connection;timer=new java.util.Timer("DRTV-Dark-deadline",true);timer.schedule(new java.util.TimerTask(){public void run(){guarded.disconnect();}},4000);
                if(connection.getResponseCode()!=200)throw new IOException("HTTP status");
                String text=limited(connection.getInputStream(),32768,begin+4000);
                ManifestVerifier.Candidate c=ManifestVerifier.verify(text,info);long highest=p.getLong("highestSeen",0);
                if(!c.metadataFresh(System.currentTimeMillis()))throw new IOException("expired metadata");
                if(c.sequence<highest){event("ROLLBACK_REJECTED");throw new IOException("rollback");}
                if(!p.edit().putLong("highestSeen",c.sequence).putString("verifiedEnvelope",text).putLong("checkedAt",now).commit())throw new IOException("preferences");
                latest=c;checkedAt=now;checkSucceeded=true;
                if(available(c)&&ManifestVerifier.usableWebsite(c.website)){
                    status="";
                    if(!manual){pending=c;readyAfter=SystemClock.elapsedRealtime()+800;main.post(this::schedule);}
                    event("VERIFIED_CANDIDATE");
                }else{status="";event("NO_COMPATIBLE_RELEASE");}
            }catch(Exception ignored){pending=null;checkSucceeded=false;status=latest==null?"Prøv igen senere.":"Gemte oplysninger · ikke en ny kontrol";event("SILENT_FAILURE");}
            finally{if(timer!=null)timer.cancel();if(connection!=null)connection.disconnect();busy.set(false);refresh();}
        },"DRTV-Dark-check");worker.setDaemon(true);worker.start();
    }
    void ignore(long sequence){
        // Back uses exactly the same seven-day reminder policy as Ignorer.
        prefs().edit().putLong("ignoredSequence",sequence).putLong("ignoredAt",reminderClock.now()).apply();event("IGNORED_7_DAYS");
    }
    void ignoreExplicitly(long sequence){
        ignore(sequence);
        ignoreConfirmationPending=true;
    }
    private void clearConfirmation(){
        if(dismissConfirmation!=null)main.removeCallbacks(dismissConfirmation);
        dismissConfirmation=null;
        if(ignoreConfirmation!=null&&ignoreConfirmation.getParent() instanceof ViewGroup)
            ((ViewGroup)ignoreConfirmation.getParent()).removeView(ignoreConfirmation);
        ignoreConfirmation=null;
    }
    private void confirmIgnore(Activity a){
        if(!ignoreConfirmationPending||foreground.get()!=a||!a.hasWindowFocus())return;
        View content=a.findViewById(android.R.id.content),nativeRoot=id(a,"main_container");
        if(!(content instanceof ViewGroup)||!(nativeRoot instanceof ViewGroup)||((ViewGroup)content).getChildCount()==0||((ViewGroup)content).getChildAt(0)!=nativeRoot)return;
        ViewGroup parent=(ViewGroup)nativeRoot;
        if(parent.getWidth()==0||parent.getHeight()==0)return;
        clearConfirmation();
        TextView message=new TextView(a);
        message.setText("Påmindelse udsat\nDu får ikke flere påmindelser om denne opdatering de næste 7 dage.\nDu kan altid søge efter opdateringer via DRTV Dark nederst på forsiden.");
        message.setTextSize(19);message.setTextColor(android.graphics.Color.WHITE);
        message.setPadding(dp(a,20),dp(a,12),dp(a,20),dp(a,12));
        message.setBackgroundColor(android.graphics.Color.rgb(38,38,38));
        message.setFocusable(false);message.setClickable(false);message.setElevation(dp(a,16));
        int width=Math.min(dp(a,820),parent.getWidth()-dp(a,48));
        message.measure(View.MeasureSpec.makeMeasureSpec(width,View.MeasureSpec.EXACTLY),View.MeasureSpec.makeMeasureSpec(parent.getHeight(),View.MeasureSpec.AT_MOST));
        parent.addView(message,new ViewGroup.LayoutParams(width,message.getMeasuredHeight()));
        message.setX((parent.getWidth()-width)/2f);message.setY(Math.max(0,parent.getHeight()-message.getMeasuredHeight()-dp(a,24)));
        ignoreConfirmation=message;ignoreConfirmationPending=false;
        dismissConfirmation=()->{clearConfirmation();event("IGNORE_CONFIRMATION_DISMISSED");};
        main.postDelayed(dismissConfirmation,6000);event("IGNORE_CONFIRMATION_SHOWN");
    }
    private void removeObservers(){
        if(readiness!=null)main.removeCallbacks(readiness);readiness=null;
        if(root!=null&&root.getViewTreeObserver().isAlive()){
            ViewTreeObserver v=root.getViewTreeObserver();if(layout!=null)v.removeOnGlobalLayoutListener(layout);if(focus!=null)v.removeOnGlobalFocusChangeListener(focus);if(scroll!=null)v.removeOnScrollChangedListener(scroll);if(window!=null)v.removeOnWindowFocusChangeListener(window);
        }root=null;layout=null;focus=null;scroll=null;window=null;
    }
    private void schedule(){
        if(readiness!=null)main.removeCallbacks(readiness);
        final long token=generation;
        readiness=()->{readiness=null;if(generation==token)reconcile();};main.postDelayed(readiness,800);
    }
    private View id(Activity a,String name){int id=a.getResources().getIdentifier(name,"id",a.getPackageName());return id==0?null:a.findViewById(id);}
    private int dp(Activity a,int value){return Math.round(value*a.getResources().getDisplayMetrics().density);}
    private WeakReference<View> entryAnchor=new WeakReference<>(null);
    private int anchorRight=View.NO_ID;
    private void unlinkEntry(){
        View anchor=entryAnchor.get();
        if(anchor!=null){anchor.setNextFocusRightId(anchorRight);anchor.setOnKeyListener(null);}
        entryAnchor.clear();
    }
    private View helpAnchor(Activity a,ViewGroup parent){
        if(!HomeGate.navigationSafe(a,parent))return null;
        int helpId=a.getResources().getIdentifier("btn_asset_link","id",a.getPackageName());
        int rowId=a.getResources().getIdentifier("row_entry_container","id",a.getPackageName());
        int listId=a.getResources().getIdentifier("gv_list","id",a.getPackageName());
        java.util.ArrayDeque<View> queue=new java.util.ArrayDeque<>();queue.add(parent);
        int budget=2000;
        while(!queue.isEmpty()&&--budget>0){
            View v=queue.removeFirst();
            if(!v.isShown())continue;
            if(v.getId()==helpId&&v instanceof TextView&&"HJÆLP".equals(((TextView)v).getText().toString().trim().toUpperCase(java.util.Locale.ROOT))&&v.getParent() instanceof View){
                View row=(View)v.getParent();
                if(row.getId()!=rowId||!row.isFocusable())continue;
                for(View ancestor=row;ancestor!=null;ancestor=ancestor.getParent() instanceof View?(View)ancestor.getParent():null)
                    if(ancestor.getId()==listId)return row;
            }
            if(v instanceof ViewGroup){ViewGroup group=(ViewGroup)v;for(int n=0;n<group.getChildCount();n++)queue.add(group.getChildAt(n));}
        }
        return null;
    }
    private void entry(Activity a){
        View content=a.findViewById(android.R.id.content),nativeRoot=id(a,"main_container");
        // DR's FocusFinder root is exactly content.childAt(0), never a sibling window.
        if(!(content instanceof ViewGroup)||!(nativeRoot instanceof ViewGroup)||((ViewGroup)content).getChildCount()==0||((ViewGroup)content).getChildAt(0)!=nativeRoot)return;
        ViewGroup parent=(ViewGroup)nativeRoot;
        Button button=(Button)parent.findViewWithTag("drtv-dark-entry-v5");
        View anchor=helpAnchor(a,parent);
        android.graphics.Rect bounds=new android.graphics.Rect();
        boolean safe=anchor!=null&&anchor.getGlobalVisibleRect(bounds)&&bounds.height()==anchor.getHeight()&&bounds.width()==anchor.getWidth();
        int[] origin=new int[2];parent.getLocationOnScreen(origin);
        int width=dp(a,150),height=dp(a,40);
        int x=safe?bounds.right-origin[0]+dp(a,16):0;
        int y=safe?bounds.centerY()-origin[1]-height/2:0;
        android.graphics.Rect proposed=new android.graphics.Rect(origin[0]+x,origin[1]+y,origin[0]+x+width,origin[1]+y+height);
        safe=safe&&x+width<=parent.getWidth()-dp(a,24)&&y>=dp(a,24)&&y+height<=parent.getHeight()-dp(a,24);
        if(safe)for(View control:parent.getFocusables(View.FOCUS_FORWARD)){
            android.graphics.Rect other=new android.graphics.Rect();
            if(control!=button&&control!=anchor&&control.isShown()&&control.getGlobalVisibleRect(other)&&android.graphics.Rect.intersects(proposed,other)&&!(control instanceof ViewGroup))safe=false;
        }
        if(!safe){
            unlinkEntry();
            if(button!=null&&button.getVisibility()!=View.GONE)button.setVisibility(View.GONE);
            return;
        }
        if(button==null){
            button=UpdateActivity.button(a,"DRTV Dark");button.setTag("drtv-dark-entry-v5");
            button.setContentDescription("DRTV Dark – uofficiel opdateringsfunktion");
            button.setTextSize(16);button.setMinHeight(0);button.setMinimumHeight(0);button.setMinWidth(0);button.setMinimumWidth(0);button.setPadding(dp(a,8),0,dp(a,8),0);button.setElevation(dp(a,12));
            button.setOnClickListener(v->{if(a.hasWindowFocus()&&foreground.get()==a&&helpAnchor(a,parent)!=null)open(a,false);});
            button.setOnKeyListener((v,key,event)->{
                if(key!=KeyEvent.KEYCODE_DPAD_LEFT&&key!=KeyEvent.KEYCODE_DPAD_UP&&key!=KeyEvent.KEYCODE_DPAD_DOWN)return false;
                View target=entryAnchor.get();if(target==null||!target.isShown())return false;
                if(event.getAction()==KeyEvent.ACTION_DOWN){
                    if(!target.requestFocus())return true;
                    // Continue vertical movement through Help's native GridView.
                    // No proprietary handler or original control is rewritten.
                    if(key!=KeyEvent.KEYCODE_DPAD_LEFT)a.dispatchKeyEvent(event);
                }
                return true;
            });
            parent.addView(button,new ViewGroup.LayoutParams(width,height));event("ENTRY_ATTACHED");
        }
        if(entryAnchor.get()!=anchor){
            unlinkEntry();entryAnchor=new WeakReference<>(anchor);anchorRight=anchor.getNextFocusRightId();
            final Button utility=button;
            // The reviewed TX1 holder/base installs click/focus listeners, no key
            // listener. Its GridView consumes the outward Right before FocusFinder.
            // Handle only that new edge; every other key retains native dispatch.
            anchor.setOnKeyListener((v,key,event)->{
                if(key!=KeyEvent.KEYCODE_DPAD_RIGHT||entryAnchor.get()!=v||utility.getVisibility()!=View.VISIBLE)return false;
                if(event.getAction()==KeyEvent.ACTION_DOWN)utility.requestFocus();return true;
            });
        }
        anchor.setNextFocusRightId(button.getId());button.setNextFocusLeftId(anchor.getId());
        button.setX(x);button.setY(y);if(button.getVisibility()!=View.VISIBLE)button.setVisibility(View.VISIBLE);
    }
    private void reconcile(){
        Activity a=foreground.get();if(a==null||a.isFinishing()||a.isDestroyed()||!a.hasWindowFocus()||opening)return;
        try{
            entry(a);ManifestVerifier.Candidate c=pending;if(c==null||info==null||SystemClock.elapsedRealtime()<readyAfter)return;
            SharedPreferences p=prefs();if(!fresh()||!available(c)||!UpdatePolicy.remind(reminderClock.now(),c.sequence,p.getLong("ignoredSequence",0),p.getLong("ignoredAt",0),p.getLong("presentedSequence",0),p.getLong("presentedAt",0)))return;
            View decor=a.getWindow().getDecorView(),focused=decor.findFocus();
            if(focused==null||!focused.isFocusable()||!focused.isEnabled()||!HomeGate.homeControl(a,focused)||!HomeGate.eligible(a,decor)){event("PLAYBACK_OR_UNREADY_SUPPRESSED");return;}
            open(a,true);
        }catch(Exception ignored){event("UI_SUPPRESSED");}
    }
    private void open(Activity a,boolean popup){
        if(opening)return;opening=true;
        try{
            returnFocus=new WeakReference<>(a.getWindow().getDecorView().findFocus());
            if(popup){ManifestVerifier.Candidate c=pending;if(c==null||!canUpdate())return;prefs().edit().putLong("presentedSequence",c.sequence).putLong("presentedAt",reminderClock.now()).apply();}
            a.startActivity(new Intent(a,UpdateActivity.class).putExtra("popup",popup));event(popup?"POPUP_STARTED":"MANAGER_OPENED");
        }finally{opening=false;}
    }
    @Override public void onActivityResumed(Activity a){try{
        if(a instanceof UpdateActivity)return;
        if(!a.getClass().getName().equals("axis.androidtv.sdk.app.MainActivity")&&!a.getClass().getName().equals("b3fixture.HomeActivity"))return;
        foreground=new WeakReference<>(a);generation++;removeObservers();root=a.getWindow().getDecorView();
        // Reconcile utility visibility immediately with header/player layout;
        // automatic update readiness keeps its existing debounce and policy.
        layout=()->{entry(a);confirmIgnore(a);schedule();};focus=(old,newFocus)->schedule();scroll=()->{entry(a);schedule();};window=has->{if(has){confirmIgnore(a);schedule();}};
        ViewTreeObserver v=root.getViewTreeObserver();v.addOnGlobalLayoutListener(layout);v.addOnGlobalFocusChangeListener(focus);v.addOnScrollChangedListener(scroll);v.addOnWindowFocusChangeListener(window);
        View f=returnFocus.get();returnFocus.clear();
        if(f!=null&&f.isAttachedToWindow()&&f.isShown()&&f.isFocusable())root.post(()->{if(foreground.get()==a&&a.hasWindowFocus()&&root!=null&&root.findFocus()==null){f.requestFocus();event("FOCUS_RESTORED");}});
        schedule();check(false);
    }catch(Exception ignored){removeObservers();}}
    @Override public void onActivityPaused(Activity a){if(foreground.get()==a){clearConfirmation();unlinkEntry();foreground.clear();generation++;removeObservers();}}
    @Override public void onActivityDestroyed(Activity a){if(foreground.get()==a){clearConfirmation();unlinkEntry();foreground.clear();generation++;removeObservers();}}
    @Override public void onActivityCreated(Activity a,Bundle b){}
    @Override public void onActivityStarted(Activity a){}
    @Override public void onActivityStopped(Activity a){}
    @Override public void onActivitySaveInstanceState(Activity a,Bundle b){}
}
