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

    public communicationToAPI(String string) {
        this.sqlmapcommand = string;
    }

    // maybe add constructor where each parameter from dialog is passed individually

    public void startScanAPI() {
        String taskIDfromcreate = createTask("GET", "http://localhost:9091");
        startScanOnAPI("POST", "http://localhost:9091", taskIDfromcreate);
    }

    public String createTask(String method, String URL) {
        URL obj = null;
        idsuccessResponse response1 = new idsuccessResponse();
        try {
            //            obj = new URL("https://jsonplaceholder.typicode.com/posts/1");
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
            if (method == "POST") {
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
                jsonObjectResponse createJsonObject = new jsonObjectResponse();
                Gson gsonSetOptions = new Gson();
                String objectToJson = gsonSetOptions.toJson(createJsonObject);
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

class jsonObjectResponse {
    private String authType = null;
    private String csrfUrl = null;
    private String csrfToken = null;
    private String getUsers = "";
    private String getPasswordHashes = "";
    private String delay = "";
    private String isDba = "";
    private String risk = "";
    private String getCurrentUser = "";
    private String getRoles = "";
    private String getPrivileges = "";
    private String testParameter = null;
    private String timeout = "";
    private String ignoreCode = null;
    private String torPort = "";
    private String level = "";
    private String getCurrentDb = "";
    private String answers = "crack=N,dict=N,continue=Y,quit=N";
    private String method = null;
    private String cookie = null;
    private String proxy = null;
    private String os = null;
    private String threads = "";
    private String url = "http://localhost/dvwa/vulnerabilities/sqli_blind/";
    private String getDbs = "";
    private String tor = "";
    private String torType = "";
    private String referer = null;
    private String retries = "";
    private String headers = null;
    private String authCred = "";
    private String timeSec = "";
    private String getHostname = "";
    private String agent = null;
    private String dbms = null;
    private String tamper = null;
    private String hpp = "";
    private String getBanner = "true";
    private String data = null;
    private String textOnly = "";



    public String getAuthType() {
        return authType;
    }

    public String getCsrfUrl() {
        return csrfUrl;
    }

    public String getCsrfToken() {
        return csrfToken;
    }

    public String getGetUsers() {
        return getUsers;
    }

    public String getGetPasswordHashes() {
        return getPasswordHashes;
    }

    public String getDelay() {
        return delay;
    }

    public String getIsDba() {
        return isDba;
    }

    public String getRisk() {
        return risk;
    }

    public String getGetCurrentUser() {
        return getCurrentUser;
    }

    public String getGetRoles() {
        return getRoles;
    }

    public String getGetPrivileges() {
        return getPrivileges;
    }

    public String getTestParameter() {
        return testParameter;
    }

    public String getTimeout() {
        return timeout;
    }

    public String getIgnoreCode() {
        return ignoreCode;
    }

    public String getTorPort() {
        return torPort;
    }

    public String getLevel() {
        return level;
    }

    public String getGetCurrentDb() {
        return getCurrentDb;
    }

    public String getAnswers() {
        return answers;
    }

    public String getMethod() {
        return method;
    }

    public String getCookie() {
        return cookie;
    }

    public String getProxy() {
        return proxy;
    }

    public String getOs() {
        return os;
    }

    public String getThreads() {
        return threads;
    }

    public String getUrl() {
        return url;
    }

    public String getGetDbs() {
        return getDbs;
    }

    public String getTor() {
        return tor;
    }

    public String getTorType() {
        return torType;
    }

    public String getReferer() {
        return referer;
    }

    public String getRetries() {
        return retries;
    }

    public String getHeaders() {
        return headers;
    }

    public String getAuthCred() {
        return authCred;
    }

    public String getTimeSec() {
        return timeSec;
    }

    public String getGetHostname() {
        return getHostname;
    }

    public String getAgent() {
        return agent;
    }

    public String getDbms() {
        return dbms;
    }

    public String getTamper() {
        return tamper;
    }

    public String getHpp() {
        return hpp;
    }

    public String getGetBanner() {
        return getBanner;
    }

    public String getData() {
        return data;
    }

    public String getTextOnly() {
        return textOnly;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public void setCsrfUrl(String csrfUrl) {
        this.csrfUrl = csrfUrl;
    }

    public void setCsrfToken(String csrfToken) {
        this.csrfToken = csrfToken;
    }

    public void setGetUsers(String getUsers) {
        this.getUsers = getUsers;
    }

    public void setGetPasswordHashes(String getPasswordHashes) {
        this.getPasswordHashes = getPasswordHashes;
    }

    public void setDelay(String delay) {
        this.delay = delay;
    }

    public void setIsDba(String isDba) {
        this.isDba = isDba;
    }

    public void setRisk(String risk) {
        this.risk = risk;
    }

    public void setGetCurrentUser(String getCurrentUser) {
        this.getCurrentUser = getCurrentUser;
    }

    public void setGetRoles(String getRoles) {
        this.getRoles = getRoles;
    }

    public void setGetPrivileges(String getPrivileges) {
        this.getPrivileges = getPrivileges;
    }

    public void setTestParameter(String testParameter) {
        this.testParameter = testParameter;
    }

    public void setTimeout(String timeout) {
        this.timeout = timeout;
    }

    public void setIgnoreCode(String ignoreCode) {
        this.ignoreCode = ignoreCode;
    }

    public void setTorPort(String torPort) {
        this.torPort = torPort;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public void setGetCurrentDb(String getCurrentDb) {
        this.getCurrentDb = getCurrentDb;
    }

    public void setAnswers(String answers) {
        this.answers = answers;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public void setProxy(String proxy) {
        this.proxy = proxy;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public void setThreads(String threads) {
        this.threads = threads;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setGetDbs(String getDbs) {
        this.getDbs = getDbs;
    }

    public void setTor(String tor) {
        this.tor = tor;
    }

    public void setTorType(String torType) {
        this.torType = torType;
    }

    public void setReferer(String referer) {
        this.referer = referer;
    }

    public void setRetries(String retries) {
        this.retries = retries;
    }

    public void setHeaders(String headers) {
        this.headers = headers;
    }

    public void setAuthCred(String authCred) {
        this.authCred = authCred;
    }

    public void setTimeSec(String timeSec) {
        this.timeSec = timeSec;
    }

    public void setGetHostname(String getHostname) {
        this.getHostname = getHostname;
    }

    public void setAgent(String agent) {
        this.agent = agent;
    }

    public void setDbms(String dbms) {
        this.dbms = dbms;
    }

    public void setTamper(String tamper) {
        this.tamper = tamper;
    }

    public void setHpp(String hpp) {
        this.hpp = hpp;
    }

    public void setGetBanner(String getBanner) {
        this.getBanner = getBanner;
    }

    public void setData(String data) {
        this.data = data;
    }

    public void setTextOnly(String textOnly) {
        this.textOnly = textOnly;
    }
    /*sqliopts = {'authType': authtype, 'csrfUrl': csrfurl, 'csrfToken': csrftoken,
    'getUsers': lusersstatus, 'getPasswordHashes': lpswdsstatus, 'delay': self._jComboDelay.getSelectedItem(),
     'isDba': isdbastatus, 'risk': self._jComboRisk.getSelectedItem(), 'getCurrentUser': custatus,
      'getRoles': lrolesstatus, 'getPrivileges': lprivsstatus, 'testParameter': paramdata,
       'timeout': self._jComboTimeout.getSelectedItem(), 'ignoreCode': ignorecodedata,
        'torPort': torport, 'level': self._jComboLevel.getSelectedItem(), 'getCurrentDb': cdbstatus,
         'answers': 'crack=N,dict=N,continue=Y,quit=N', 'method': httpmethod, 'cookie': cookiedata,
          'proxy': proxy, 'os': os, 'threads': self._jComboThreads.getSelectedItem(), 'url': self._jTextFieldURL.getText(),
           'getDbs': ldbsstatus, 'tor': torstatus, 'torType': tortype, 'referer': refererdata,
            'retries': self._jComboRetry.getSelectedItem(), 'headers': custheaderdata, 'authCred': authcred,
             'timeSec': self._jComboTimeSec.getSelectedItem(), 'getHostname': hostnamestatus, 'agent': uadata, 'dbms': dbms,
              'tamper': tamperdata, 'hpp': hppstatus, 'getBanner': 'true', 'data': postdata, 'textOnly': textonlystatus}*/
}
