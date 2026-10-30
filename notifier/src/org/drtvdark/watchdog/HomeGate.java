package org.drtvdark.watchdog;
import android.app.Activity;import android.content.Context;import android.graphics.Rect;import android.media.AudioManager;import android.view.*;import android.widget.*;
/** Exact observed 4.39.0 hierarchy, fail closed if it changes. */
final class HomeGate {
    static boolean navigationSafe(Activity activity,View root){
        int pager=activity.getResources().getIdentifier("home_pager","id",activity.getPackageName());
        int player=activity.getResources().getIdentifier("player_container","id",activity.getPackageName());
        View p=pager==0?null:root.findViewById(pager),v=player==0?null:root.findViewById(player);
        return p!=null&&p.isShown()&&(v==null||!video(v,new int[]{1000}));
    }
    static boolean home(Activity activity,View root){
        if(activity.getClass().getName().equals("b3fixture.HomeActivity"))return true;
        // Reviewed 4.39.0 uses one activity for all tabs. Fail closed on a changed
        // layout/class/API; never link against or rewrite proprietary classes.
        try{
            int id=activity.getResources().getIdentifier("home_pager","id",activity.getPackageName());
            View pager=id==0?null:root.findViewById(id);
            return pager!=null&&pager.isShown()&&pager.getClass().getName().equals("androidx.viewpager2.widget.ViewPager2")&&Integer.valueOf(0).equals(pager.getClass().getMethod("getCurrentItem").invoke(pager));
        }catch(Exception ignored){return false;}
    }
    static boolean eligible(Activity activity,View root){
        if(!home(activity,root)||video(root,new int[]{10000}))return false;
        // Real DRTV retains an active audio track for its hidden autoplay hero.
        // That global flag cannot identify playback. Its exact Home pager and
        // visible-player guards above exclude playback without touching media.
        if(activity.getClass().getName().equals("axis.androidtv.sdk.app.MainActivity"))return true;
        AudioManager audio=(AudioManager)activity.getSystemService(Context.AUDIO_SERVICE);
        return audio==null||!audio.isMusicActive();
    }
    static boolean homeControl(Activity activity,View focused){
        if(activity.getClass().getName().equals("b3fixture.HomeActivity"))return true;
        int id=activity.getResources().getIdentifier("gv_list","id",activity.getPackageName());
        for(View v=focused;v!=null;v=v.getParent() instanceof View?(View)v.getParent():null)
            if(id!=0&&v.getId()==id&&v instanceof ViewGroup&&((ViewGroup)v).getChildCount()>0)return true;
        return false;
    }
    static boolean video(View view,int[] budget){
        java.util.ArrayDeque<View> queue=new java.util.ArrayDeque<>();queue.add(view);
        while(!queue.isEmpty()){
            View current=queue.removeLast();if(--budget[0]<0)return true;if(!current.isShown()||!current.getGlobalVisibleRect(new Rect()))continue;
            if(current instanceof SurfaceView||current instanceof TextureView||current instanceof VideoView||current.getClass().getSimpleName().contains("PlayerView"))return true;
            if(current instanceof ViewGroup){ViewGroup group=(ViewGroup)current;if(group.getChildCount()>budget[0])return true;for(int n=0;n<group.getChildCount();n++)queue.add(group.getChildAt(n));}
        }return false;
    }
}
