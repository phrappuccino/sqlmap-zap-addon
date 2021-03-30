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
import java.util.concurrent.TimeUnit;

import org.parosproxy.paros.view.View;
import org.parosproxy.paros.Constant;

public class CommunicationToAPI {
    JsonObjectResponse optionsObject;
    private int http_resp = 0;

    public int getHttp_resp() {
        return http_resp;
    }

    public void setHttp_resp(int http_resp) {
        this.http_resp = http_resp;
    }

    public CommunicationToAPI(JsonObjectResponse optionsObject) {
        this.optionsObject = optionsObject;
    }

    public void startScanAPI(String urlPort) {
        setHttp_resp(0);
        String taskIDfromcreate = createTask("GET", "http://" + urlPort);
        if(getHttp_resp() == 200) {
            setOptionsOnAPI("POST", "http://" + urlPort, taskIDfromcreate);
            startScanOnAPI("POST", "http://" + urlPort, taskIDfromcreate);
            try {
                TimeUnit.SECONDS.sleep(3);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            while (true) {
                String statusFromF = getStatusFromAPI("GET", "http://" + urlPort, taskIDfromcreate);
                int i = 0;
                i++;
                if (i > 20) {
                    break;
                }
                if (statusFromF.equals("terminated")) {
                    View.getSingleton()
                            .getOutputPanel()
                            .append("getting data after scan" + "\n");
                    getDataFromAPI("GET", "http://" + urlPort, taskIDfromcreate);
                    break;
                }
                try {
                    TimeUnit.SECONDS.sleep(3);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }else {
            View.getSingleton().getOutputPanel().append("API could not be reached!\n");
        }
        setHttp_resp(0);
    }

    public String createTask(String method, String URL) {
        URL obj = null;
        IdSuccessResponse response1 = new IdSuccessResponse();
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
                JsonObjectResponse createJsonObject = new JsonObjectResponse();
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
            setHttp_resp(responseCode);
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

            response1 = gson.fromJson(String.valueOf(response), IdSuccessResponse.class);

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

            IdSuccessResponse response1 = gson.fromJson(String.valueOf(response), IdSuccessResponse.class);

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

            IdSuccessResponse response1 = gson.fromJson(String.valueOf(response), IdSuccessResponse.class);

            View.getSingleton()
                    .getOutputPanel()
                    .append("taskid is: " + response1.getTaskid() + "\n");
            View.getSingleton().getOutputPanel().append(response + "\n");*/


        } else {
            View.getSingleton().getOutputPanel().append("GET request not worked\n");
        }
    }

    public String getStatusFromAPI(String method, String URL, String passedTaskID) {
        URL obj = null;
        IdSuccessResponse response1 = new IdSuccessResponse();
        try {
            obj = new URL(URL + "/scan/" + passedTaskID + "/status"); // ip:Port/scan/ID/status       ip:Port/scan/ID/data
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
                JsonObjectResponse createJsonObject = new JsonObjectResponse();
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

            response1 = gson.fromJson(String.valueOf(response), IdSuccessResponse.class);

            /*View.getSingleton()
                    .getOutputPanel()
                    .append("taskid is: " + response1.getTaskid() + "\n");
            View.getSingleton().getOutputPanel().append(response + "\n");*/

//            if (response1.getTaskid().length() > 0 && response1.getSuccess() == "true"){
//                response1.setSuccess("failed");
//                View.getSingleton().getOutputPanel().append("creating task with POST\n");
//                createTask("POST", URL, response1.getTaskid());
//            }

            View.getSingleton()
                    .getOutputPanel()
                    .append("inside get status is: " + response1.getStatus() + "\n");
        } else {
            View.getSingleton().getOutputPanel().append("GET request not worked\n");
        }
        return response1.getStatus();
    }

    public void getDataFromAPI(String method, String URL, String passedTaskID) {
        URL obj = null;
//        IdSuccessResponse response1 = new IdSuccessResponse();
        try {
            obj = new URL(URL + "/scan/" + passedTaskID + "/data"); // ip:Port/scan/ID/status       ip:Port/scan/ID/data
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
                JsonObjectResponse createJsonObject = new JsonObjectResponse();
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

//            View.getSingleton()
//                    .getOutputPanel()
//                    .append("raw data from scan is: " + response + "\n");

//            View.getSingleton().showMessageDialog(Constant.messages.getString(ExtensionSqlMap.PREFIX + ".popup.msg", response));

            View.getSingleton().getOutputPanel().append("before new object generate report\n");

            GenerateReport generateReport = new GenerateReport(response.toString(),passedTaskID);

            View.getSingleton().getOutputPanel().append("before set attributes\n");
            generateReport.setAttributes();
            String vulndetails = generateReport.getVulndetails();

            View.getSingleton()
                    .getOutputPanel()
                    .append("vulndetails are: " + vulndetails + "\n");

//            Gson gson = new Gson();
//
//            response1 = gson.fromJson(String.valueOf(response), IdSuccessResponse.class);

            /*View.getSingleton()
                    .getOutputPanel()
                    .append("taskid is: " + response1.getTaskid() + "\n");
            View.getSingleton().getOutputPanel().append(response + "\n");*/

//            if (response1.getTaskid().length() > 0 && response1.getSuccess() == "true"){
//                response1.setSuccess("failed");
//                View.getSingleton().getOutputPanel().append("creating task with POST\n");
//                createTask("POST", URL, response1.getTaskid());
//            }

//            View.getSingleton()
//                    .getOutputPanel()
//                    .append("inside get status is: " + response1.getStatus() + "\n");
        } else {
            View.getSingleton().getOutputPanel().append("GET request not worked\n");
        }
//        return response1.getStatus();
    }
}

class IdSuccessResponse {
    private String taskid = "";
    private String success = "";
    private String status = "";

    public String getTaskid() {
        return taskid;
    }

    public String getSuccess() {
        return success;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setTaskid(String taskid) {
        this.taskid = taskid;
    }

    public void setSuccess(String success) {
        this.success = success;
    }
}