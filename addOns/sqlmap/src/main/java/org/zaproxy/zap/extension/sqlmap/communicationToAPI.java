package org.zaproxy.zap.extension.sqlmap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;

import com.google.gson.Gson;
import org.parosproxy.paros.view.View;

import java.net.URL;

public class communicationToAPI {
    String sqlmapcommand;
    public communicationToAPI(String string) {
        this.sqlmapcommand = string;
    }

    //maybe add constructor where each parameter from dialog is passed individually
    public void sendReq() {
        URL obj = null;
        try {
//            obj = new URL("https://jsonplaceholder.typicode.com/posts/1");
            obj = new URL("http://localhost:9091/task/new");
        } catch (MalformedURLException e) {
            e.printStackTrace();
            View.getSingleton().getOutputPanel().append("cought malformed url");
        }
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) obj.openConnection();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            //Hier auf POST oder jeweilige HTTP-Methode wechseln die benötigt wird
            con.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }

        int responseCode = 0;
        try {
            responseCode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        //View.getSingleton().getOutputPanel().append("GET Response Code :: " + responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(
                        con.getInputStream()));
            } catch (IOException e) {
                e.printStackTrace();
            }
            String inputLine = null;
            StringBuffer response = new StringBuffer();

            while (true) {
                try {
                    if (!((inputLine = in.readLine()) != null)) break;
                } catch (IOException e) {
                    e.printStackTrace();
                }
                response.append(inputLine);
            }
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            Gson gson = new Gson();

            firstResponse response1 = gson.fromJson(String.valueOf(response), firstResponse.class);

            View.getSingleton().getOutputPanel().append("taskid is: " + response1.getTaskid() + "\n");
        } else {
            View.getSingleton().getOutputPanel().append("GET request not worked");
        }
    }
}

class firstResponse {
    private String taskid;
    private String success;

    public String getTaskid() {
        return taskid;
    }

    public String getSuccess() {
        return success;
    }
}