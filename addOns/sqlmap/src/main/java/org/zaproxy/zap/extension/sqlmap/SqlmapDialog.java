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

import java.awt.*;
import javax.swing.*;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class SqlmapDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String FIELD_SQLMAP_NAME_PATTERN = "sqlmap.dialog.field.namepattern";
    private static final String FIELD_SQLMAP_NAME_TARGETURL = "sqlmap.dialog.field.url";
    private static final String FIELD_SQLMAP_NAME_TARGETPOSTDATA = "sqlmap.dialog.field.postdata";
    private static final String FIELD_SQLMAP_NAME_TARGETCOOKIES = "sqlmap.dialog.field.cookies";
    private static final String FIELD_SQLMAP_NAME_USERAGENT = "sqlmap.dialog.field.useragent";
    private static final String FIELD_SQLMAP_NAME_LEVEL = "sqlmap.dialog.field.level";
    private static final String FIELD_SQLMAP_NAME_RISK = "sqlmap.dialog.field.risk";
    private static final String FIELD_SQLMAP_NAME_PARAMPOLLUTION =
            "sqlmap.dialog.option.parampollution";
    private static final String FIELD_SQLMAP_NAME_LISTUSERS = "sqlmap.dialog.option.listusers";
    private static final String FIELD_SQLMAP_NAME_CURRENTUSER = "sqlmap.dialog.option.currentuser";
    private static final String FIELD_SQLMAP_NAME_LISTPASSWORDS =
            "sqlmap.dialog.option.listpasswords";
    private static final String FIELD_SQLMAP_NAME_CURRENTDB = "sqlmap.dialog.option.currentdb";
    private static final String FIELD_SQLMAP_NAME_LISTPRIVS = "sqlmap.dialog.option.listprivs";
    private static final String FIELD_SQLMAP_NAME_HOSTNAME = "sqlmap.dialog.option.hostname";
    private static final String FIELD_SQLMAP_NAME_LISTROLES = "sqlmap.dialog.option.listroles";
    private static final String FIELD_SQLMAP_NAME_ISDBA = "sqlmap.dialog.option.isdba";
    private static final String FIELD_SQLMAP_NAME_LISTDBS = "sqlmap.dialog.option.listdbs";
    private static final String FIELD_SQLMAP_NAME_THREADS = "sqlmap.dialog.field.threads";
    private static final String FIELD_SQLMAP_NAME_RETRIES = "sqlmap.dialog.field.retires";
    private static final String FIELD_SQLMAP_NAME_APIIPPORT = "sqlmap.dialog.field.api-ip-port";
    private static final String FIELD_SQLMAP_NAME_DBMSBACKEND = "sqlmap.dialog.field.dbmsbackend";
    private static final String FIELD_SQLMAP_NAME_OS = "sqlmap.dialog.field.os";
    private static final String FIELD_SQLMAP_NAME_TESTPARAMETERS = "sqlmap.dialog.field.testparams";

    private static final String[] TAB_LABELS = {"sqlmap.dialog.tab.options"};
    private static final String[] LEVEL_CHOICES = {"1", "2", "3", "4", "5"};
    private static final String[] RISK_CHOICES = {"1", "2", "3"};
    private static final String[] THREADS_CHOICES = {
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
    };
    private static final String[] RETRIES_CHOICES = {
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
    };
    private static final String[] DBMS_BACKEND_CHOICES = {
        "Any",
        "MySQL",
        "Oracle",
        "PostgreSQL",
        "Microsoft SQL Server",
        "Microsoft Access",
        "SQLite",
        "Firebird",
        "Sybase",
        "SAP MaxDB",
        "DB2",
        "Informix",
        "MariaDB",
        "Percona",
        "MemSQL",
        "TiDB",
        "CockroachDB",
        "HSQLDB",
        "H2",
        "MonetDB",
        "Apache Derby",
        "Amazon Redshift",
        "Vertica",
        "Mckoi",
        "Presto",
        "Altibase",
        "MimerSQL",
        "CrateDB",
        "Greenplum",
        "Drizzle",
        "Apache Ignite",
        "Cubrid",
        "InterSystems Cache",
        "IRIS",
        "eXtremeDB",
        "FrontBase"
    };
    private static final String[] OS_CHOICES = {"Any", "Linux", "Windows"};
    private static final int TAB_OPTIONS = 0;

    private ExtensionSqlMap extension = null;
    private JButton[] extraButtons = null;
    private DefaultListModel<Context> contextsModel;
    private DefaultListModel<String> sitesModel;
    private JList<Context> contextsSelector;
    private JList<String> sitesSelector;
    private communicationToAPI communicationToAPI1;

    public SqlmapDialog(ExtensionSqlMap ext, Frame owner) {
        super(owner, "sqlmap.dialog.title", DisplayUtils.getScaledDimension(600, 800), TAB_LABELS);
        this.extension = ext;
        reset(true);
    }

    public void init(HttpMessage httpMessage) {
        this.removeAllFields();
        this.contextsModel = null;
        this.sitesModel = null;
        this.contextsSelector = null;
        this.sitesSelector = null;

        this.addTextField(TAB_OPTIONS, FIELD_SQLMAP_NAME_APIIPPORT, "localhost:9091");
        this.addTextField(
                TAB_OPTIONS,
                FIELD_SQLMAP_NAME_TARGETURL,
                httpMessage.getRequestHeader().getURI().toString());
        this.addMultilineField(
                TAB_OPTIONS,
                FIELD_SQLMAP_NAME_TARGETPOSTDATA,
                httpMessage.getRequestBody().toString());
        this.addTextField(
                TAB_OPTIONS,
                FIELD_SQLMAP_NAME_TARGETCOOKIES,
                httpMessage.getCookieParamsAsString());
        addRemainingFields();
    }

    private void addRemainingFields() {
        //        this.addTextField(TAB_OPTIONS, FIELD_SQLMAP_NAME_USERAGENT, "");
        this.addTextField(TAB_OPTIONS, FIELD_SQLMAP_NAME_TESTPARAMETERS, "");

        this.addComboField(TAB_OPTIONS, FIELD_SQLMAP_NAME_LEVEL, LEVEL_CHOICES, "1");
        this.addComboField(TAB_OPTIONS, FIELD_SQLMAP_NAME_RISK, RISK_CHOICES, "1");

        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_PARAMPOLLUTION, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_LISTUSERS, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_CURRENTUSER, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_LISTPASSWORDS, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_CURRENTDB, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_HOSTNAME, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_ISDBA, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_LISTDBS, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_LISTROLES, false);
        this.addCheckBoxField(TAB_OPTIONS, FIELD_SQLMAP_NAME_LISTPRIVS, false);

        this.addComboField(TAB_OPTIONS, FIELD_SQLMAP_NAME_THREADS, THREADS_CHOICES, "5");
        this.addComboField(TAB_OPTIONS, FIELD_SQLMAP_NAME_RETRIES, RETRIES_CHOICES, "3");

        this.addComboField(TAB_OPTIONS, FIELD_SQLMAP_NAME_DBMSBACKEND, DBMS_BACKEND_CHOICES, "Any");
        this.addComboField(TAB_OPTIONS, FIELD_SQLMAP_NAME_OS, OS_CHOICES, "Any");

        this.addPadding(TAB_OPTIONS);
        this.pack();
    }

    public void init() {
        this.removeAllFields();
        this.contextsModel = null;
        this.sitesModel = null;
        this.contextsSelector = null;
        this.sitesSelector = null;

        this.addTextField(TAB_OPTIONS, FIELD_SQLMAP_NAME_APIIPPORT, "127.0.0.1:8081");
        this.addTextField(TAB_OPTIONS, FIELD_SQLMAP_NAME_TARGETURL, "");
        this.addMultilineField(TAB_OPTIONS, FIELD_SQLMAP_NAME_TARGETPOSTDATA, "");
        this.addTextField(TAB_OPTIONS, FIELD_SQLMAP_NAME_TARGETCOOKIES, "");
        addRemainingFields();
    }

    @Override
    public void save() {}

    @Override
    public String validateFields() {
        return null;
    }

    private void reset(boolean refreshUi) {
        if (refreshUi) {
            String string = "Hello";
            int returncode = 2;
            // sqliopts = {'authType': authtype, 'csrfUrl': csrfurl, 'csrfToken': csrftoken,
            // 'getUsers': lusersstatus, 'getPasswordHashes': lpswdsstatus, 'delay':
            // self._jComboDelay.getSelectedItem(), 'isDba': isdbastatus, 'risk':
            // self._jComboRisk.getSelectedItem(), 'getCurrentUser': custatus, 'getRoles':
            // lrolesstatus, 'getPrivileges': lprivsstatus, 'testParameter': paramdata, 'timeout':
            // self._jComboTimeout.getSelectedItem(), 'ignoreCode': ignorecodedata, 'torPort':
            // torport, 'level': self._jComboLevel.getSelectedItem(), 'getCurrentDb': cdbstatus,
            // 'answers': 'crack=N,dict=N,continue=Y,quit=N', 'method': httpmethod, 'cookie':
            // cookiedata, 'proxy': proxy, 'os': os, 'threads':
            // self._jComboThreads.getSelectedItem(), 'url': self._jTextFieldURL.getText(),
            // 'getDbs': ldbsstatus, 'tor': torstatus, 'torType': tortype, 'referer': refererdata,
            // 'retries': self._jComboRetry.getSelectedItem(), 'headers': custheaderdata,
            // 'authCred': authcred, 'timeSec': self._jComboTimeSec.getSelectedItem(),
            // 'getHostname': hostnamestatus, 'agent': uadata, 'dbms': dbms, 'tamper': tamperdata,
            // 'hpp': hppstatus, 'getBanner': 'true', 'data': postdata, 'textOnly': textonlystatus}
            String jsonInputString = "{'authType': null, }";
            // {    "taskid": "e8540cc7c36f3c65",     "success": true}
            jsonObjectResponse optionsObject = new jsonObjectResponse();
            communicationToAPI1 = new communicationToAPI(string, optionsObject);
            String APIUrl = this.getStringValue(FIELD_SQLMAP_NAME_APIIPPORT);
            optionsObject.setUrl(this.getStringValue(FIELD_SQLMAP_NAME_TARGETURL));
            optionsObject.setData(this.getStringValue(FIELD_SQLMAP_NAME_TARGETPOSTDATA));
            optionsObject.setCookie(this.getStringValue(FIELD_SQLMAP_NAME_TARGETCOOKIES));
            optionsObject.setTestParameter(this.getStringValue(FIELD_SQLMAP_NAME_TESTPARAMETERS));
            optionsObject.setUrl(this.getStringValue(FIELD_SQLMAP_NAME_TARGETURL));
            optionsObject.setUrl(this.getStringValue(FIELD_SQLMAP_NAME_TARGETURL));

            communicationToAPI1.startScanAPI(APIUrl);

            //            communicationToAPI commu = null;
            //            returncode = commu.sendReq();
            //            init();
            //            repaint();
        }
    }

    @Override
    public JButton[] getExtraButtons() {
        if (extraButtons == null) {
            JButton startButton =
                    new JButton(Constant.messages.getString("sqlmap.dialog.button.start"));
            startButton.addActionListener(e -> reset(true));

            extraButtons = new JButton[] {startButton};
        }

        return extraButtons;
    }
}