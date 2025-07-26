package org.tsicoop.dpdpcms.framework;

import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;


public class AsyncEmailTask extends TimerTask {

    String apiUrl = null;
    String apiUser = null;
    String apipassword = null;
    String senderPersonal = null;
    String from = null;
    String to = null;
    String subject = null;
    String msgbody = null;

    public AsyncEmailTask(String apiUrl,
                          String apiUser,
                          String apipassword,
                          String senderPersonal,
                          String from,
                          String to,
                          String subject,
                          String msgbody) {
        this.apiUrl = apiUrl;
        this.apiUser = apiUser;
        this.apipassword = apipassword;
        this.senderPersonal = senderPersonal;
        this.from = from;
        this.to = to;
        this.subject = subject;
        this.msgbody = msgbody;

        Timer timer = new Timer();
        timer.schedule(this, 1000);
    }


    private void sendMail() throws Exception {
        Properties props = new Properties();
        msgbody = URLEncoder.encode(msgbody, "UTF-8");
        msgbody = msgbody.replaceAll(" ", "%20");
        senderPersonal = (senderPersonal != null) ? senderPersonal.replaceAll(" ", "%20") : from.substring(0, from.indexOf('@'));
        subject = URLEncoder.encode(subject, "UTF-8");
        String message = apiUrl + "?api_user=" + apiUser + "&api_key=" + apipassword + "" +
                "&to=" + to + "&subject=" + subject + "&html=" + msgbody + "&from=" + from + "&fromname=" + senderPersonal;

        URL url = new URL(message);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream());
        writer.close();
        System.out.println(connection.getResponseCode());
        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
            System.out.println(connection.getResponseCode());
        } else {
            // Server returned HTTP error code.
            //log.error("ResponseCode" + connection.getResponseCode());
        }
    }

    @Override
    public void run() {
        // TODO Auto-generated method stub
        try {
            this.sendMail();
        } catch (Exception e1) {
            //log.error("", e1);
            try {
                Thread.sleep(20 * 1000);
            } catch (InterruptedException ie1) {
            }
            try {
                this.sendMail();
            } catch (Exception e2) {
                //log.error("", e2);
                //log.info("Attempt #2.. Sending to " + to);
                try {
                    Thread.sleep(20 * 1000);
                } catch (InterruptedException ie2) {
                    //log.error("", ie2);
                }
                try {
                    //log.info("Attempt #3.. Sending to " + to);
                    this.sendMail();
                } catch (Exception e3) {
                    // giving up
                    //log.error("", e3);
                    //log.info("Giving up.. Sending to " + to);
                }
            }
        }
    }
}
