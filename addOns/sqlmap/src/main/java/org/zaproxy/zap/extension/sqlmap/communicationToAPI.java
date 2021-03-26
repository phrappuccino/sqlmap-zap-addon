/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.sqlmap;

import com.google.gson.Gson;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import org.parosproxy.paros.view.View;

public class communicationToAPI {
    String sqlmapcommand;
    jsonObjectResponse optionsObject;

    public communicationToAPI(String string, jsonObjectResponse optionsObject) {
        this.sqlmapcommand = string;
        this.optionsObject = optionsObject;
    }

    public void startScanAPI(String urlPort) {
        String taskIDfromcreate = createTask("GET", "http://" + urlPort);
        setOptionsOnAPI("POST", "http://" + urlPort, taskIDfromcreate);
        startScanOnAPI("POST", "http://" + urlPort, taskIDfromcreate);
    }

    public String createTask(String method, String URL) {
        URL obj = null;
        idsuccessResponse response1 = new idsuccessResponse();
        try {
            obj = new URL(URL + "/task/new");
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
            // Hier auf POST oder jeweilige HTTP-Methode wechseln die benötigt wird
            con.setRequestMethod(method);
            /*if (method == "POST") {
                View.getSingleton().getOutputPanel().append("inside post con method before properties\n");
                con.setRequestProperty("Content-Type", "application/json; utf-8");
                con.setRequestProperty("Accept", "application/json");
                con.setDoOutput(true);
                jsonObjectResponse createJsonObject = new jsonObjectResponse();
                Gson gsonSetOptions = new Gson();
                String objectToJson = gsonSetOptions.toJson(createJsonObject);
                try(OutputStream os = con.getOutputStream()) {
                    View.getSingleton().getOutputPanel().append("try os\n");
                    byte[] input = objectToJson.getBytes("utf-8");
                    os.write(input, 0, input.length);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }*/
        } catch (ProtocolException e) {
            e.printStackTrace();
        }

        int responseCode = 0;
        try {
            responseCode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        // View.getSingleton().getOutputPanel().append("GET Response Code :: " + responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(con.getInputStream()));
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

            response1 = gson.fromJson(String.valueOf(response), idsuccessResponse.class);

            View.getSingleton()
                    .getOutputPanel()
                    .append("taskid is: " + response1.getTaskid() + "\n");
            View.getSingleton().getOutputPanel().append(response + "\n");

//            if (response1.getTaskid().length() > 0 && response1.getSuccess() == "true"){
//                response1.setSuccess("failed");
//                View.getSingleton().getOutputPanel().append("creating task with POST\n");
//                createTask("POST", URL, response1.getTaskid());
//            }
        } else {
            View.getSingleton().getOutputPanel().append("GET request not worked\n");
        }
        return response1.getTaskid();
    }

    public void setOptionsOnAPI(String method, String URL, String passedTaskID) {
        URL obj = null;
        try {
            //            obj = new URL("https://jsonplaceholder.typicode.com/posts/1");
            obj = new URL(URL + "/option/" + passedTaskID + "/set");
        } catch (MalformedURLException e) {
            e.printStackTrace();
            View.getSingleton().getOutputPanel().append("cought malformed url in scan start");
        }
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) obj.openConnection();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            // Hier auf POST oder jeweilige HTTP-Methode wechseln die benötigt wird
            con.setRequestMethod(method);
            if (method == "POST") {
                View.getSingleton().getOutputPanel().append("inside post con method before properties\n");
                con.setRequestProperty("Content-Type", "application/json; utf-8");
                con.setRequestProperty("Accept", "application/json");
                con.setDoOutput(true);
                Gson gsonSetOptions = new Gson();
                String objectToJson = gsonSetOptions.toJson(optionsObject);
                View.getSingleton().getOutputPanel().append(objectToJson + "\n");
                try(OutputStream os = con.getOutputStream()) {
                    View.getSingleton().getOutputPanel().append("try os\n");
                    byte[] input = objectToJson.getBytes("utf-8");
                    os.write(input, 0, input.length);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (ProtocolException e) {
            e.printStackTrace();
        }

        int responseCode = 0;
        try {
            responseCode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        // View.getSingleton().getOutputPanel().append("GET Response Code :: " + responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(con.getInputStream()));
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

            /*Gson gson = new Gson();

            idsuccessResponse response1 = gson.fromJson(String.valueOf(response), idsuccessResponse.class);

            View.getSingleton()
                    .getOutputPanel()
                    .append("taskid is: " + response1.getTaskid() + "\n");
            View.getSingleton().getOutputPanel().append(response + "\n");*/


        } else {
            View.getSingleton().getOutputPanel().append("GET request not worked\n");
        }
    }

    public void startScanOnAPI(String method, String URL, String passedTaskID) {
        URL obj = null;
        try {
            //            obj = new URL("https://jsonplaceholder.typicode.com/posts/1");
            obj = new URL(URL + "/scan/" + passedTaskID + "/start");
        } catch (MalformedURLException e) {
            e.printStackTrace();
            View.getSingleton().getOutputPanel().append("cought malformed url in scan start");
        }
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) obj.openConnection();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            // Hier auf POST oder jeweilige HTTP-Methode wechseln die benötigt wird
            con.setRequestMethod(method);
            if (method == "POST") {
                View.getSingleton().getOutputPanel().append("inside post con method before properties\n");
                con.setRequestProperty("Content-Type", "application/json; utf-8");
                con.setRequestProperty("Accept", "application/json");
                con.setDoOutput(true);
                Gson gsonSetOptions = new Gson();
                String objectToJson = gsonSetOptions.toJson(optionsObject);
                View.getSingleton().getOutputPanel().append(objectToJson + "\n");
                try(OutputStream os = con.getOutputStream()) {
                    View.getSingleton().getOutputPanel().append("try os\n");
                    byte[] input = objectToJson.getBytes("utf-8");
                    os.write(input, 0, input.length);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (ProtocolException e) {
            e.printStackTrace();
        }

        int responseCode = 0;
        try {
            responseCode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        // View.getSingleton().getOutputPanel().append("GET Response Code :: " + responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(con.getInputStream()));
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

            /*Gson gson = new Gson();

            idsuccessResponse response1 = gson.fromJson(String.valueOf(response), idsuccessResponse.class);

            View.getSingleton()
                    .getOutputPanel()
                    .append("taskid is: " + response1.getTaskid() + "\n");
            View.getSingleton().getOutputPanel().append(response + "\n");*/


        } else {
            View.getSingleton().getOutputPanel().append("GET request not worked\n");
        }
    }
}

class idsuccessResponse {
    private String taskid = "";
    private String success = "";

    public String getTaskid() {
        return taskid;
    }

    public String getSuccess() {
        return success;
    }

    public void setTaskid(String taskid) {
        this.taskid = taskid;
    }

    public void setSuccess(String success) {
        this.success = success;
    }
}