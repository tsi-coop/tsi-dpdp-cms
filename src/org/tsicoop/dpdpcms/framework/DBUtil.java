package org.tsicoop.dpdpcms.framework;

import java.sql.Date;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

public class DBUtil {

    public static String[] getSafeArray(java.sql.Array array) throws SQLException {
        String[] retval = {};
        if(array != null){
            retval = (String[]) array.getArray();
        }
        return retval;
    }

    public static String convertSqlDateToString(Date sqlDate) {
        if (sqlDate == null) {
            return null; // Handle null input as needed
        }
        SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy");
        return dateFormat.format(sqlDate);
    }

    public static String getTimeAgo(Instant pastInstant) {
        Instant now = Instant.now();
        Duration duration = Duration.between(pastInstant, now);

        long seconds = duration.getSeconds();
        long minutes = TimeUnit.SECONDS.toMinutes(seconds);
        long hours = TimeUnit.SECONDS.toHours(seconds);
        long days = TimeUnit.SECONDS.toDays(seconds);
        long weeks = days / 7;
        long months = days/30;
        long years = days/365;
        String secs = null;
        String mtss = null;
        String hrss = null;
        String dayss = null;
        String weekss = null;
        String monthss = null;
        String yearss = null;


        if (seconds < 60) {
            if(seconds == 1)
                secs=seconds + " second ago";
            else
                secs=seconds + " seconds ago";
            return secs;
        } else if (minutes < 60) {
            if(minutes == 1)
                mtss=minutes + " minute ago";
            else
                mtss=minutes + " minutes ago";
            return mtss;
        } else if (hours < 24) {
            if(hours == 1)
                hrss=hours + " hour ago";
            else
                hrss=hours + " hours ago";
            return hrss;
        } else if (days < 7){
            if(days == 1)
                dayss=days + " day ago";
            else
                dayss=days + " days ago";
            return dayss;
        } else if(weeks < 4){
            if(weeks == 1)
                weekss=weeks + " week ago";
            else
                weekss=weeks + " weeks ago";
            return weekss;
        } else if (months < 12){
            if(months == 1)
                monthss=months + " month ago";
            else
                monthss=months + " months ago";
            return monthss;
        } else {
            if(years == 1)
                yearss=years + " year ago";
            else
                yearss=years + " years ago";
            return yearss;
        }
    }
}
