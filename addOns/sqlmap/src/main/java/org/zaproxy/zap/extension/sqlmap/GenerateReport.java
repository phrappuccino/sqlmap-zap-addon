package org.zaproxy.zap.extension.sqlmap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.parosproxy.paros.view.View;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class GenerateReport {
    private String taskID;      //ID on API
    private String vulndetails; //targetURL + parameters data|value|query
    private String payloads = "";
    private String dbtype = "";
    private String banner = "";
    private String currentUser = "";
    private String currentDB = "";
    private String hostname = "";
    private String isdba = "";
    private String listUsers = "";
    private String listPasswords;
    private String listPrivs;
    private String listRoles;
    private String listDBS = "";
    private String jsonStringFromAPI;
    private JsonObject jsonObject;

    public GenerateReport(String jsonStringFromAPI, String taskID) {
        setJsonStringFromAPI(jsonStringFromAPI);
        setTaskID(taskID);
    }

    public void setAttributes() {
        setJsonObject(getJsonStringFromAPI());
        JsonElement data = getJsonObject().get("data");         //root element "data"
        JsonArray dataArray = data.getAsJsonArray();            //data[] from root element

        for (int i = 0; i < dataArray.size(); i++) {
            View.getSingleton().getOutputPanel().append("array size "+dataArray.size() + " iteration " + i + "\n");
            JsonElement dataOuterArray = dataArray.get(i);
            JsonElement typeFromData = dataOuterArray.getAsJsonObject().get("type");
            JsonElement valueElement = dataOuterArray.getAsJsonObject().get("value");
            if (typeFromData.toString().equals("0")){
                View.getSingleton().getOutputPanel().append("type is: " + typeFromData.toString() + "\n");
                setVulndetails("<ul><li>URL: " + valueElement.getAsJsonObject().get("url").toString() + "</li><li>Parameter: " + valueElement.getAsJsonObject().get("query").toString() + "</li></ul>");
            }
            else if (typeFromData.toString().equals("1")){
//                View.getSingleton().getOutputPanel().append("type is: " + typeFromData.toString() + "\n");
                JsonArray valueArray = valueElement.getAsJsonArray();
                for (int j = 0; j < valueArray.size(); j++){
                    View.getSingleton().getOutputPanel().append("value array size is: " + valueArray.size() + "\n");
                    JsonElement valueOuterArray = valueArray.get(j);
                    JsonElement dbtype = valueOuterArray.getAsJsonObject().get("dbms");
                    View.getSingleton().getOutputPanel().append("db type is: "+dbtype.toString()+"\n");
                    if (getDbtype().length() == 0){
                        setDbtype(dbtype.toString());
                    }
                    else if (!getDbtype().equals(dbtype.toString())){
                        setDbtype(getDbtype() + ", or " + dbtype.toString());
                    }
                    View.getSingleton().getOutputPanel().append("getDbtype after get: "+getDbtype()+"\n");
                    JsonElement innerData = valueOuterArray.getAsJsonObject().get("data");
                    View.getSingleton().getOutputPanel().append("size is " + innerData.getAsJsonObject().size() + "\n");

                    for (int k = 0; k < 10; k++){
                        boolean test = innerData.getAsJsonObject().has(String.valueOf(k));
                        if (test){
                            JsonElement innerDataEnum = innerData.getAsJsonObject().get(String.valueOf(k));
                            JsonElement innerPayload = innerDataEnum.getAsJsonObject().get("payload");
                            setPayloads(getPayloads() + "<li>" + innerPayload.toString() + "</li>");
                        }
                    }
                    setPayloads("<ul>"+getPayloads()+"</ul><BR>");
                    View.getSingleton().getOutputPanel().append("payloads are: " + getPayloads());
                }
            }
            else if (typeFromData.toString().equals("3")){
                if (!valueElement.getAsString().equals("")) {
                    setBanner(valueElement.getAsString() + "<BR>");
                }
//                View.getSingleton().getOutputPanel().append("banner is: " + getBanner());
            }
            else if (typeFromData.toString().equals("4")){
                if (!valueElement.getAsString().equals("")) {
                    setCurrentUser("Current User: " + valueElement.getAsString() + "<BR>");
                }
//                View.getSingleton().getOutputPanel().append("current user is: " + getCurrentUser());
            }
            else if (typeFromData.toString().equals("5")){
                if (!valueElement.getAsString().equals("")) {
                    setCurrentDB("Current Database: " + valueElement.getAsString() + "<BR>");
                }
                View.getSingleton().getOutputPanel().append("current db is: " + getCurrentDB());
            }
            else if (typeFromData.toString().equals("6")){
                if (!valueElement.getAsString().equals("")) {
                    setHostname("Hostname: " + valueElement.getAsString() + "(empty if enumeration failed)<BR>");
                }
                View.getSingleton().getOutputPanel().append("current hostname is: " + getHostname());
            }
            else if (typeFromData.toString().equals("7")){
                if (!valueElement.getAsString().equals("")) {
                    if (valueElement.getAsString().equals("true")) {
                        setIsdba("Is DBA: Yes<BR>");
                    } else {
                        setIsdba("Is DBA: No<BR>");
                    }
                }
            }
            else if (typeFromData.toString().equals("8")){
                if (!valueElement.getAsString().equals("")) {
                    JsonArray valueArray = valueElement.getAsJsonArray();
                    for (int l = 0; l < valueArray.size(); l++) {
                        JsonElement temp = valueArray.get(l);
                        setListUsers(getListUsers() + "<li>" + temp.toString() + "</li>");
                    }
                    setListUsers("Users:<ul>" + getListUsers() + "</ul><BR>");
                }
            }
            else if (typeFromData.toString().equals("12")){
                JsonArray valueArray = valueElement.getAsJsonArray();
                for (int m = 0; m < valueArray.size(); m++){
                    JsonElement temp = valueArray.get(m);
                    View.getSingleton().getOutputPanel().append("databases are: " + temp.toString() + "\n");
                    setListDBS(getListDBS() + "<li>" + temp.toString() + "</li>");
                }
                setListDBS("Databases:<ul>" + getListDBS() + "</ul><BR>");
            }
        }
        String reportAsString =             "<html><head><title>SQLMap Scan - " + getTaskID() + "</title></head><body>";
        reportAsString = reportAsString + "<h1>SQLMap Scan Finding</h1><br><p>The application has been found to be vulnerable to SQL injection by SQLMap.</p><br>";
        reportAsString = reportAsString + "<p>Vulnerable URL and Parameter:</p><p>"+getVulndetails()+"</p>";
        reportAsString = reportAsString + "<p>The following payloads successfully identified SQL injection vulnerabilities:</p>;";
        reportAsString = reportAsString + "<p>"+getPayloads()+"</p><p>Enumerated Data:</p>";
        if (!getDbtype().equals("")){
            reportAsString = reportAsString + "<p>Databasetype: "+getDbtype()+": "+getBanner()+"</p>";
        }
        if (getCurrentUser().equals("")){
            reportAsString = reportAsString + "<p>"+getCurrentUser()+"</p>";
        }
        if (!getCurrentDB().equals("")){
            reportAsString = reportAsString + "<p>"+getCurrentDB()+"</p>";
        }
        if (!getHostname().equals("")){
            reportAsString = reportAsString + "<p>"+getHostname()+"</p>";
        }
        if (!getIsdba().equals("")){
            reportAsString = reportAsString + "<p>"+getIsdba()+"</p>";
        }
        if (!getListUsers().equals("")){
            reportAsString = reportAsString + "<p>"+getListUsers()+"</p>";
        }
        if (!getListDBS().equals("")){
            reportAsString = reportAsString + "<p>"+getListDBS()+"</p>";
        }
        reportAsString = reportAsString + "</body></html>";
        /*+listPasswords+"</p><p>"+listPrivs+"</p><p>"+listRoles+"</p>"<p>"*/
        writeToFile(reportAsString, getTaskID());
    }

    private void writeToFile(String string, String fileName) {
        fileName = System.getProperty("user.home") + "\\Documents\\" + fileName + ".html";
        try {
            File myFile = new File(fileName);
            if(myFile.createNewFile()){
                View.getSingleton().getOutputPanel().append("File created: " + fileName + "\n");
            }else {
                View.getSingleton().getOutputPanel().append("File already exsits!\n");
            }
            FileWriter writer = new FileWriter(fileName);
            writer.write(string);

            writer.close();
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    public JsonObject getJsonObject() {
        return jsonObject;
    }

    public void setJsonObject(String jsonStringFromAPI) {
        this.jsonStringFromAPI = jsonStringFromAPI;
        this.jsonObject = JsonParser.parseString(jsonStringFromAPI).getAsJsonObject();
    }

    public String getJsonStringFromAPI() {
        return jsonStringFromAPI;
    }

    public void setJsonStringFromAPI(String jsonStringFromAPI) {
        this.jsonStringFromAPI = jsonStringFromAPI;
    }

    public String getTaskID() {
        return taskID;
    }

    public void setTaskID(String taskID) {
        this.taskID = taskID;
    }

    public String getVulndetails() {
        return vulndetails;
    }

    public void setVulndetails(String vulndetails) {
        this.vulndetails = vulndetails;
    }

    public String getPayloads() {
        return payloads;
    }

    public void setPayloads(String payloads) {
        this.payloads = payloads;
    }

    public String getDbtype() {
        return dbtype;
    }

    public void setDbtype(String dbtype) {
        this.dbtype = dbtype;
    }

    public String getBanner() {
        return banner;
    }

    public void setBanner(String banner) {
        this.banner = banner;
    }

    public String getCurrentUser() {
        return currentUser;
    }

    public void setCurrentUser(String currentUser) {
        this.currentUser = currentUser;
    }

    public String getCurrentDB() {
        return currentDB;
    }

    public void setCurrentDB(String currentDB) {
        this.currentDB = currentDB;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getIsdba() {
        return isdba;
    }

    public void setIsdba(String isdba) {
        this.isdba = isdba;
    }

    public String getListUsers() {
        return listUsers;
    }

    public void setListUsers(String listUsers) {
        this.listUsers = listUsers;
    }

    public String getListPasswords() {
        return listPasswords;
    }

    public void setListPasswords(String listPasswords) {
        this.listPasswords = listPasswords;
    }

    public String getListPrivs() {
        return listPrivs;
    }

    public void setListPrivs(String listPrivs) {
        this.listPrivs = listPrivs;
    }

    public String getListRoles() {
        return listRoles;
    }

    public void setListRoles(String listRoles) {
        this.listRoles = listRoles;
    }

    public String getListDBS() {
        return listDBS;
    }

    public void setListDBS(String listDBS) {
        this.listDBS = listDBS;
    }
}
