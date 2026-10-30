package org.drtvdark.watchdog;

import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

/** B13: called only at the two audited presentation binding boundaries. */
public final class ThemeCorrections {
    private static final int CHARCOAL=0xff242424, LIGHT=0xffeeeeee;
    private ThemeCorrections(){}
    private static Object call(Object o,String name)throws ReflectiveOperationException{return o.getClass().getMethod(name).invoke(o);}
    private static View view(View root,String name){
        int id=root.getResources().getIdentifier(name,"id",root.getContext().getPackageName());
        return id==0?null:root.findViewById(id);
    }
    public static boolean categoryHeader(String page,String text,String link){
        return page!=null&&text!=null&&!text.trim().isEmpty()&&(link==null||link.isEmpty())
            &&(page.startsWith("/kategorier/")||"Hjælp".equals(text.trim()));
    }
    public static boolean childPromotion(String page,String id,String template){
        return "ED1".equals(template)&&(("/ramasjang".equals(page)&&"85aebd1".equals(id))
            ||("/minisjang".equals(page)&&"291ba1f".equals(id)));
    }
    public static void header(Object holder){try{
        Object vm=holder.getClass().getField("entryVm").get(holder);
        if(!categoryHeader((String)call(vm,"getPagePath"),(String)call(vm,"getImageText"),(String)call(vm,"getLink")))return;
        View root=(View)holder.getClass().getField("itemView").get(holder);
        View container=view(root,"img_container"), title=view(root,"title_view");
        if(container==null||!(title instanceof TextView))return;
        Object image=call(container,"getImageView");
        if(!(image instanceof ImageView))return;
        // Compositor alpha survives Glide's asynchronous drawable cross-fade alpha.
        // The remote header image is not edited, cached differently or redistributed.
        ((ImageView)image).setAlpha(0f);
        ((ImageView)image).setBackgroundColor(CHARCOAL);
        View row=view(root,"h9_row_layout");if(row!=null)row.setBackgroundColor(CHARCOAL);
        ((TextView)title).setTextColor(ColorStateList.valueOf(LIGHT));
        // H9's original focus background, bottom line, sizing and click listener stay active.
    }catch(ReflectiveOperationException|ClassCastException ignored){/* Unknown upstream shape: leave it alone. */}}
    private static int dp(View v,int n){return Math.round(n*v.getResources().getDisplayMetrics().density);}
    private static GradientDrawable panel(View v,boolean focused){
        GradientDrawable d=new GradientDrawable();d.setColor(CHARCOAL);
        if(focused)d.setStroke(dp(v,2),LIGHT);return d;
    }
    public static void promotion(Object holder){try{
        Object vm=holder.getClass().getField("entryVm").get(holder),entry=call(vm,"getPageEntry");
        if(!childPromotion((String)call(vm,"getPagePath"),(String)call(entry,"getId"),(String)call(entry,"getTemplate")))return;
        View root=(View)holder.getClass().getField("itemView").get(holder);
        View row=view(root,"row_entry_container"),text=view(root,"row_layout"),image=view(root,"img_hero");
        View heading=view(root,"txt_list_title"),description=view(root,"txt_list_custom_tag_line");
        if(!(row instanceof ViewGroup)||text==null||image==null||!(heading instanceof TextView)||!(description instanceof TextView))return;
        // This precise ED1 is a single remote promotional bitmap, not programme tiles.
        // Keep its original row action and focus listener; the image subtree is hidden.
        if(!(image.getParent() instanceof View))return;
        ((View)image.getParent()).setVisibility(View.GONE);
        text.setVisibility(View.VISIBLE);text.setPadding(dp(text,24),dp(text,18),dp(text,24),dp(text,18));
        TextView h=(TextView)heading,d=(TextView)description;
        h.setText("Se videre med en børneprofil");d.setText("Opret en profil på ikonet oppe i højre hjørne");
        h.setVisibility(View.VISIBLE);d.setVisibility(View.VISIBLE);
        h.setTextColor(LIGHT);d.setTextColor(LIGHT);h.setTextSize(22);d.setTextSize(18);
        row.setPadding(dp(row,36),dp(row,10),dp(row,36),dp(row,10));
        ViewGroup.LayoutParams p=row.getLayoutParams();p.height=ViewGroup.LayoutParams.WRAP_CONTENT;row.setLayoutParams(p);
        // Original ED1 focus code changes backgroundColor, so use a separate foreground.
        StateListDrawable states=new StateListDrawable();
        GradientDrawable focus=new GradientDrawable();focus.setColor(Color.TRANSPARENT);focus.setStroke(dp(row,2),LIGHT);
        states.addState(new int[]{android.R.attr.state_focused},focus);
        states.addState(new int[]{},new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
        row.setForeground(states);text.setBackground(panel(text,false));
        row.setTag("drtv-dark-child-promotion-b13");
    }catch(ReflectiveOperationException|ClassCastException ignored){/* Exact component match required. */}}
}
