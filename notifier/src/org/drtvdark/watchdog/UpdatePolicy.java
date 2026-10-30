package org.drtvdark.watchdog;

/** Pure policy, also exercised on the host. No device identifiers or networking. */
public final class UpdatePolicy {
    public static final long DAY_MS = 24L * 60 * 60 * 1000;
    public static final long REMINDER_MS = 7 * DAY_MS;
    public static final long PRESENTATION_MS = 10 * 60 * 1000;
    /** Reminder policy clock; network deadlines/throttling use their own clocks. */
    public interface Clock { long now(); }
    public static final String CURRENT="Ingen nyere DRTV Dark fundet";
    public static final String UPDATE="En ny version af DRTV Dark er klar";
    public static final String UNKNOWN="Kunne ikke kontrollere opdateringer";
    public static String darkStatus(boolean fresh,boolean trusted,boolean available,
            long installed,long latest,boolean sameVersion){
        if(!fresh||!trusted)return UNKNOWN;
        if(available)return UPDATE;
        return installed==latest&&sameVersion?CURRENT:UNKNOWN;
    }
    public static boolean officialAhead(boolean fresh,long official,long installed,long supported){
        return fresh&&official>installed&&official>supported;
    }
    private UpdatePolicy() {}
    public static boolean due(long now, long lastAttempt) {
        return now >= 0 && (lastAttempt == 0 || (now >= lastAttempt && now - lastAttempt >= DAY_MS));
    }
    public static boolean available(boolean released, boolean artifactsVerified,
            boolean compatible, boolean sameSigner, long candidate, long installed,
            long minimum, long highestSeen, long dismissed) {
        return released && artifactsVerified && compatible && sameSigner
            && candidate > installed && candidate > dismissed && candidate >= highestSeen
            && minimum >= 0 && installed >= minimum;
    }
    /** Invalid/future timestamps suppress conservatively; the store rebases them once. */
    public static boolean remind(long now,long sequence,long ignored,long ignoredAt,long shown,long shownAt) {
        if(now<=0||sequence<=0)return false;
        if(sequence==ignored&&(ignoredAt<=0||ignoredAt>now||now-ignoredAt<REMINDER_MS))return false;
        return sequence!=shown||(shownAt>0&&shownAt<=now&&now-shownAt>=PRESENTATION_MS);
    }
    public static boolean officialFresh(long now,long verifiedAt) {
        return verifiedAt>0&&now>=verifiedAt&&now-verifiedAt<=30*DAY_MS;
    }
}
