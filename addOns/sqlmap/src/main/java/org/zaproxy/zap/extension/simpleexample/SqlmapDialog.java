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
package org.zaproxy.zap.extension.simpleexample;

import java.awt.*;
import javax.swing.*;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class SqlmapDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String FIELD_SQLMAP_NAME_PATTERN = "sqlmap.dialog.field.namepattern";

    private static final String[] TAB_LABELS = {"sqlmap.dialog.tab.options"};
    private static final int TAB_OPTIONS = 0;

    private ExtensionSqlMap extension = null;
    private JButton[] extraButtons = null;
    private DefaultListModel<Context> contextsModel;
    private DefaultListModel<String> sitesModel;
    private JList<Context> contextsSelector;
    private JList<String> sitesSelector;

    public SqlmapDialog(ExtensionSqlMap ext, Frame owner) {
        super(owner, "sqlmap.dialog.title", DisplayUtils.getScaledDimension(600, 500), TAB_LABELS);
        this.extension = ext;
        reset(true);
    }

    public void init() {
        this.removeAllFields();
        this.contextsModel = null;
        this.sitesModel = null;
        this.contextsSelector = null;
        this.sitesSelector = null;

        this.addTextField(FIELD_SQLMAP_NAME_PATTERN, "add first textfield");

        this.pack();
    }

    @Override
    public void save() {}

    @Override
    public String validateFields() {
        return null;
    }

    private void reset(boolean refreshUi) {
        if (refreshUi) {
            init();
            repaint();
        }
    }
}
