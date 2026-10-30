package org.drtvdark.watchdog;

import android.app.Activity;
import android.content.Context;
import android.graphics.*;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.*;
import android.widget.*;

/** One nonexported, native dialog Activity in the existing DR TV task. */
public final class UpdateActivity extends Activity {
    private Watchdog manager;
    private LinearLayout content;
    private TextView primary,status,officialNote;
    private TextView darkInstalled,darkLatest,tvLabel,tvInstalled,tvLatest;
    private Button update;
    private boolean automatic;
    private int page;
    private long sequence;
    static Button button(Context context,String label){
        Button b=new Button(context);b.setId(View.generateViewId());b.setText(label);b.setAllCaps(false);b.setTextSize(19);b.setTextColor(Color.WHITE);b.setFocusable(true);
        b.setPadding(20,6,20,6);paint(b,false);b.setOnFocusChangeListener((v,focused)->paint(b,focused));return b;
    }
    private static void paint(Button b,boolean focus){GradientDrawable d=new GradientDrawable();d.setColor(focus?Color.rgb(0,82,128):Color.rgb(55,55,55));d.setCornerRadius(5);d.setStroke(focus?4:1,focus?Color.WHITE:Color.GRAY);b.setBackground(d);}
    @Override public void onCreate(Bundle saved){
        setTheme(android.R.style.Theme_Material_Dialog_Alert);super.onCreate(saved);requestWindowFeature(Window.FEATURE_NO_TITLE);
        manager=Watchdog.instance;if(manager==null){finish();return;}
        automatic=saved==null?getIntent().getBooleanExtra("popup",false):saved.getBoolean("automatic");
        sequence=saved==null?(manager.latest()==null?0:manager.latest().sequence):saved.getLong("sequence");
        page=saved==null?(automatic?1:0):saved.getInt("page");
        setFinishOnTouchOutside(false);getWindow().addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        render();getWindow().setLayout(Math.min(1100,getResources().getDisplayMetrics().widthPixels-120),ViewGroup.LayoutParams.WRAP_CONTENT);
    }
    @Override protected void onResume(){super.onResume();if(manager!=null)manager.attach(this);}
    @Override protected void onPause(){if(manager!=null)manager.detach(this);super.onPause();}
    @Override protected void onSaveInstanceState(Bundle b){b.putBoolean("automatic",automatic);b.putLong("sequence",sequence);b.putInt("page",page);super.onSaveInstanceState(b);}
    private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextColor(Color.WHITE);t.setTextSize(size);t.setPadding(0,6,0,6);content.addView(t);return t;}
    private Button action(String label,Runnable run){Button b=button(this,label);LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT);p.setMargins(0,7,0,0);content.addView(b,p);b.setOnClickListener(v->run.run());return b;}
    private void close(){if(automatic&&sequence>0)manager.ignore(sequence);finish();}
    private void render(){
        content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);content.setPadding(34,22,34,22);content.setBackgroundColor(Color.rgb(24,24,24));
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(false);scroll.addView(content);setContentView(scroll);primary=null;status=null;update=null;
        if(page==1){
            text("DRTV Dark-opdatering",25);
            TableLayout versions=table();row(versions,new String[]{"Din version",manager.info()==null?"Ukendt":manager.info().darkVersion},false);row(versions,new String[]{"Nyeste version",manager.latest()==null?"Ukendt":manager.latest().darkVersion},false);
            LinearLayout row=new LinearLayout(this);row.setOrientation(LinearLayout.HORIZONTAL);content.addView(row);
            Button yes=button(this,"Opdater"),no=button(this,"Ignorer i 7 dage");
            LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1);p.setMargins(5,12,5,0);row.addView(yes,p);row.addView(no,new LinearLayout.LayoutParams(p));
            yes.setNextFocusRightId(no.getId());no.setNextFocusLeftId(yes.getId());yes.setNextFocusLeftId(no.getId());no.setNextFocusRightId(yes.getId());
            yes.setOnClickListener(v->{if(manager.canUpdate()&&manager.latest().sequence==sequence){page=2;render();}});no.setOnClickListener(v->{if(automatic&&sequence>0)manager.ignoreExplicitly(sequence);finish();});
            yes.setEnabled(manager.canUpdate());(yes.isEnabled()?yes:no).requestFocus();return;
        }
        text("DRTV Dark",25);
        if(page==2){
            if(!manager.canUpdate()||(automatic&&manager.latest().sequence!=sequence)){text("Opdateringsadressen er ikke tilgængelig.",20);action("Tilbage",this::back).requestFocus();return;}
            String address=manager.latest().website;
            text("Åbn siden på din telefon eller computer.",20);text(address,21);
            try{
                Bitmap bitmap=qr(address,280);ImageView image=new ImageView(this);image.setImageBitmap(bitmap);image.setContentDescription("QR-kode til "+address);image.setScaleType(ImageView.ScaleType.FIT_CENTER);content.addView(image,new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,280));
            }catch(Exception ignored){text("QR-kode kunne ikke vises. Brug adressen ovenfor.",17);}
            action("Tilbage",this::back).requestFocus();return;
        }
        primary=text("",22);
        TableLayout versions=table();row(versions,new String[]{"App","Installeret","Nyeste"},true);
        TextView[] dark=row(versions,new String[]{"DRTV Dark","",""},false),tv=row(versions,new String[]{"DR TV","",""},false);
        darkInstalled=dark[1];darkLatest=dark[2];tvLabel=tv[0];tvInstalled=tv[1];tvLatest=tv[2];
        officialNote=text("",16);status=text("",16);
        Button check=action("Søg efter opdateringer",()->manager.check(true));check.setTag("manual-check");
        update=action("Opdater",()->{if(manager.canUpdate()){page=2;render();}});
        action("Tilbage",this::back);refresh();check.requestFocus();
    }
    /** Actual native table: each row shares equal fixed column fractions. */
    private TableLayout table(){TableLayout t=new TableLayout(this);t.setStretchAllColumns(true);t.setShrinkAllColumns(true);content.addView(t,new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT));return t;}
    private TextView[] row(TableLayout table,String[] labels,boolean heading){
        TableRow row=new TableRow(this);TextView[] cells=new TextView[labels.length];
        for(int n=0;n<labels.length;n++){
            TextView cell=new TextView(this);cell.setText(labels[n]);cell.setTextColor(heading?Color.LTGRAY:Color.WHITE);cell.setTextSize(heading?17:20);cell.setPadding(0,7,14,7);cell.setGravity(Gravity.TOP|Gravity.START);
            if(!heading&&n>0)cell.setTypeface(null,android.graphics.Typeface.BOLD);
            cell.setSingleLine(false);cell.setHorizontallyScrolling(false);cell.setBreakStrategy(android.text.Layout.BREAK_STRATEGY_SIMPLE);
            row.addView(cell,new TableRow.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1));cells[n]=cell;
        }table.addView(row,new TableLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT));return cells;
    }
    void refresh(){
        if(primary==null)return;
        ManifestVerifier.Info i=manager.info();ManifestVerifier.Candidate c=manager.latest();
        // Installed Dark and underlying DR version come only from authenticated
        // embedded config, after it has matched PackageManager and own signer.
        darkInstalled.setText(i==null?"Ukendt":i.darkVersion);tvInstalled.setText(i==null?"Ukendt":i.originalVersion);
        // In coexistence mode this is Dark's upstream source, not a claim about
        // the separately installed official app's current Play version.
        tvLabel.setText(i!=null&&!i.applicationPackage.equals(i.originalPackage)?"DR TV-kilde":"DR TV");
        darkLatest.setText(manager.fresh()&&manager.trusted()?c.darkVersion:"Ikke verificeret");
        primary.setText(manager.primaryStatus());
        String note="",official="Ikke verificeret";long now=System.currentTimeMillis();
        if(c!=null&&!c.official.version.isEmpty()){
            ManifestVerifier.Official o=c.official;
            boolean fresh=manager.fresh()&&UpdatePolicy.officialFresh(now,o.verifiedAt);
            if(fresh){
                official=o.version;
                if(i!=null&&UpdatePolicy.officialAhead(manager.trusted(),o.versionCode,i.originalCode,c.supportedOriginalCode))note="DR TV har en nyere version. Der findes endnu ikke en DRTV Dark til den nye version.";
            }else if(o.status.equals("verified"))note="Tidligere verificeret DR TV: "+o.version+" · "+o.date+" · ikke bekræftet aktuel";
            else if(o.status.equals("candidate"))note="Mulig DR TV-version: "+o.version+" · ikke verificeret";
        }
        tvLatest.setText(official);officialNote.setText(note);officialNote.setVisibility(note.isEmpty()?View.GONE:View.VISIBLE);
        String detail=manager.status();if(c!=null&&!manager.fresh()&&detail.isEmpty())detail="Gemte oplysninger · ikke en ny kontrol";
        status.setText(detail);status.setVisibility(detail.isEmpty()?View.GONE:View.VISIBLE);
        boolean show=manager.canUpdate();if(!show&&update.hasFocus()){View next=content.findViewWithTag("manual-check");if(next!=null)next.requestFocus();}update.setVisibility(show?View.VISIBLE:View.GONE);
    }
    private void back(){if(page==2&&!automatic){page=0;render();}else close();}
    @Override public void onBackPressed(){back();}
    private static Bitmap qr(String address,int size)throws Exception {
        // The exact reviewed original already includes ZXing. Access its public
        // encoder API reflectively, without copying or rewriting those classes.
        Class<?> format=Class.forName("com.google.zxing.BarcodeFormat");Object type=format.getField("QR_CODE").get(null);
        Object writer=Class.forName("com.google.zxing.qrcode.QRCodeWriter").getConstructor().newInstance();
        Object matrix=writer.getClass().getMethod("encode",String.class,format,int.class,int.class).invoke(writer,address,type,size,size);
        java.lang.reflect.Method get=matrix.getClass().getMethod("get",int.class,int.class);
        int[] pixels=new int[size*size];for(int y=0;y<size;y++)for(int x=0;x<size;x++)pixels[y*size+x]=(Boolean)get.invoke(matrix,x,y)?Color.BLACK:Color.WHITE;
        return Bitmap.createBitmap(pixels,size,size,Bitmap.Config.ARGB_8888);
    }
}
