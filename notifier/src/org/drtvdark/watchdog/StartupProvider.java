package org.drtvdark.watchdog;

import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

/** Nonexported initializer. No network, disk scan, new permission or service here. */
public final class StartupProvider extends ContentProvider {
    @Override public boolean onCreate(){try{Application app=(Application)getContext().getApplicationContext();if(app!=null)app.registerActivityLifecycleCallbacks(new Watchdog(app));}catch(Throwable ignored){}return true;}
    @Override public Cursor query(Uri uri,String[] p,String s,String[] a,String order){return null;}
    @Override public String getType(Uri uri){return null;}
    @Override public Uri insert(Uri uri,ContentValues values){throw new UnsupportedOperationException();}
    @Override public int delete(Uri uri,String selection,String[] args){throw new UnsupportedOperationException();}
    @Override public int update(Uri uri,ContentValues values,String selection,String[] args){throw new UnsupportedOperationException();}
}
