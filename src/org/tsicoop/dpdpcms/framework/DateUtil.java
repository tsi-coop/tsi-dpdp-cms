package org.tsicoop.dpdpcms.framework;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class DateUtil {

    public static String getDateKey(Date date) {
        String key = (date.getMonth() + 1) + "/" + date.getDate() + "/" + (1900 + date.getYear());
        return key;
    }

    public static String getMonthKey(Date date) {
        String key = (1900 + date.getYear()) + "/" + (date.getMonth() + 1);
        return key;
    }

    public static Date nextday(Date date) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.DATE, 1);  // number of days to add
        return c.getTime();
    }

    public static Date nextmonth(Date date) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.MONTH, 1);  // number of days to add
        return c.getTime();
    }

    public static Date prevday(Date date) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.DATE, -1);  // number of days
        return c.getTime();
    }

    public static Date earlierDate(Date date, int num) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.DATE, -num);  // number of days
        return c.getTime();
    }

    public static String getDateKey(String start, String end) {
        return start + "-" + end;
    }

    public static int getNumDaysBtwn(Date start, Date end) {
        return (int) ((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    }

    public static int getNumMinsBtwn(Date start, Date end) {
        return (int) ((end.getTime() - start.getTime()) / (1000 * 60));
    }

    public static String getTimePeriodDisplay(Date start, Date end, String period) {
        String timeperiod = "";
        if (period.equalsIgnoreCase("Hour")) {
            timeperiod = start.getHours() + "";
        } else if (period.equalsIgnoreCase("Day")) {
            timeperiod = start.getDate() + getSuffix(start.getDate());
        } else if (period.equalsIgnoreCase("Week")) {
            timeperiod = start.getDate() + "-" + end.getDate();
        } else if (period.equalsIgnoreCase("Month")) {
            timeperiod = displayMonth2(start);
        } else if (period.equalsIgnoreCase("Year")) {
            timeperiod = (1900 + start.getYear()) + "";
        }
        System.out.println("timeperiod:" + timeperiod);
        return timeperiod;
    }

    public static String displayMonth(Date date) {
        String display = "";
        SimpleDateFormat sdf = new SimpleDateFormat("MMM");
        display = sdf.format(date) + " " + ((1900 + date.getYear()));
        return display;
    }

    public static String displayMonth2(Date date) {
        String display = "";
        SimpleDateFormat sdf = new SimpleDateFormat("MMM");
        display = sdf.format(date) + " " + ((1900 + date.getYear()) % 1000);
        return display;
    }

    public static String getSuffix(int dayOfMonth) {
        String suffix = "";
        switch (dayOfMonth) {
            case 1:
            case 21:
            case 31:
                suffix = "st";
                break;
            case 2:
            case 22:
                suffix = "nd";
                break;
            case 3:
            case 23:
                suffix = "rd";
                break;
            default:
                suffix = "th";
        }
        return suffix;
    }

    public static Date getNextTimePeriod(Date date, String period) {
        if (period.equalsIgnoreCase("Hour")) {
            return getNextHour(date);
        } else if (period.equalsIgnoreCase("Day")) {
            return getNextDay(date);
        } else if (period.equalsIgnoreCase("Week")) {
            return getNextWeekStart(date);
        } else if (period.equalsIgnoreCase("Month")) {
            return getNextMonth(date);
        } else if (period.equalsIgnoreCase("Year")) {
            return getNextYear(date);
        } else {
            return getNextDay(date);
        }
    }


    private static Date getNextHour(Date date) {
        Calendar mycal = new GregorianCalendar();
        mycal.setTime(date);
        mycal.add(Calendar.HOUR, 1);
        return mycal.getTime();
    }

    private static Date getNextDay(Date date) {
        Calendar mycal = new GregorianCalendar();
        mycal.setTime(date);
        mycal.add(Calendar.DATE, 1);
        return mycal.getTime();
    }

    private static Date getWeekEnd(Date date) {
        Calendar now = new GregorianCalendar();
        now.setTime(date);
        int weekday = now.get(Calendar.DAY_OF_WEEK);
        if (weekday != Calendar.SUNDAY) {
            // calculate how much to add
            // the 2 is the difference between Saturday and Monday
            int days = (Calendar.SATURDAY - weekday + 1) % 7;
            now.add(Calendar.DAY_OF_YEAR, days);
        }
        // now is the date you want
        Date end = now.getTime();
        System.out.println(end);
        return end;
    }

    private static Date getNextWeekStart(Date date) {
        System.out.println("Inside Next Week Start");
        Calendar now = new GregorianCalendar();
        now.setTime(date);
        int weekday = now.get(Calendar.DAY_OF_WEEK);
        System.out.println("weekday:" + weekday);

        if (weekday != Calendar.MONDAY) {
            // calculate how much to add
            // the 2 is the difference between Saturday and Monday
            int days = (Calendar.SATURDAY - weekday + 2) % 7;
            now.add(Calendar.DAY_OF_YEAR, days);
        } else {
            now.add(Calendar.DAY_OF_YEAR, 7);
        }
        // now is the date you want
        Date start = now.getTime();
        System.out.println(start);
        return start;
    }

    private static Date getNextMonth(Date date) {
        Calendar mycal = new GregorianCalendar();
        mycal.setTime(date);
        mycal.add(Calendar.MONTH, 1);
        return mycal.getTime();
    }

    private static Date getNextYear(Date date) {
        Calendar mycal = new GregorianCalendar();
        mycal.setTime(date);
        mycal.add(Calendar.YEAR, 1);
        return mycal.getTime();
    }

    public static String determinePeriod(Date start, Date end) {
        String period = "";
        int numdays = DateUtil.getNumDaysBtwn(start, end);
        if (start.getTime() == end.getTime()) {
            period = "Hour";
        } else if (numdays > 1 && numdays < 14) {
            period = "Day";
        } else if (numdays >= 14 && numdays < 62) {
            period = "Week";
        } else if (numdays >= 62 && numdays < 365) {
            period = "Month";
        } else if (numdays > 365) {
            period = "Year";
        }
        return period;
    }

    public static DateFormat getDateFormat() {
        DateFormat format = null;

        try {
            format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        } catch (Exception e) {
            format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
        }
        return format;
    }

    public static void main(String[] args) {
        new DateUtil().getWeekEnd(new Date("2014/1/19"));
    }
}
