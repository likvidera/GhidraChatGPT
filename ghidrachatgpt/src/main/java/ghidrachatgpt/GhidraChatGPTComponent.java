/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ghidrachatgpt;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.BorderLayout;
import java.lang.Thread;
import javax.swing.*;
import resources.Icons;

import docking.Tool;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.util.Msg;
import ghidra.app.script.AskDialog;
import java.lang.Integer;

public class GhidraChatGPTComponent extends ComponentProvider {

    private JPanel panel;
    private DockingAction action;
    private GhidraChatGPTPlugin gcgplugin;
	static final String FUNCTION_ID_NAME = "GhidraChatGPT";

    public GhidraChatGPTComponent(Plugin plugin, String owner) {
        super(plugin.getTool(), owner, owner);
        gcgplugin = (GhidraChatGPTPlugin) plugin;
        createActions();
    }

    public String askForOpenAIToken() {
        AskDialog<String> dialog = new AskDialog<>("OpenAI API token not configured!", "Enter OpenAI API Token:", AskDialog.STRING, "");
        if (dialog.isCanceled()) {
            return null;
        }
        return dialog.getValueAsString();
    }

    public int askForMaxTokens() {
        AskDialog<String> dialog = new AskDialog<>("Set the max tokens per ChatGPT request", "Enter the max amount of tokens:", AskDialog.STRING, Integer.toString(gcgplugin.getMaxTokens()));
        if (dialog.isCanceled()) {
            return 0;
        }
        return Integer.parseInt(dialog.getValueAsString());
    }

    private void createActions() {
        // Identify function
        action = new DockingAction("GCGIdentifyFunction", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                new Thread(() -> {
                    gcgplugin.identifyFunction();
                }).start();
            }
        };

        action.setEnabled(true);
        action.setDescription("Identify the function with the help of ChatGPT");
        action.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Identify Function" }));
        dockingTool.addAction(action);

        // Find vulnerabilities
        action = new DockingAction("GCGFindVulnerabilities", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                new Thread(() -> {
                    gcgplugin.findVulnerabilities();
                }).start();
            }
        };

        action.setEnabled(true);
        action.setDescription("Find vulnerabilities in the function with the help of ChatGPT");
        action.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Find Vulnerabilities" }));
        dockingTool.addAction(action);

        // Beautify function
        action = new DockingAction("GCGBeatuifyFunction", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                new Thread(() -> {
                    gcgplugin.beautifyFunction();
                }).start();
            }
        };

        action.setEnabled(true);
        action.setDescription("Beautify the function with the help of ChatGPT");
        action.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Beautify Function" }));
        dockingTool.addAction(action);

        // Update OpenAI Token
        action = new DockingAction("GCGUpdateOpenAIToken", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (gcgplugin.setToken(askForOpenAIToken())) {
                    gcgplugin.ok("Updated the current OpenAI API Token");
                }
            }
        };

        action.setEnabled(true);
        action.setDescription("Update the current OpenAI API Token");
        action.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Settings", "Update OpenAI Token" }));
        dockingTool.addAction(action);

        // Update Max Tokens
        action = new DockingAction("GCGUpdateMaxTokens", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                int maxTokens = askForMaxTokens();
                if (maxTokens > 0) {
                    gcgplugin.setMaxTokens(maxTokens);
                    gcgplugin.ok(String.format("Updated max tokens per ChatGPT request to %s", maxTokens));
                }
            }
        };

        action.setEnabled(true);
        action.setDescription("Update the max tokens per ChatGPT request");
        action.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Settings", "Update Max Tokens" }));
        dockingTool.addAction(action);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}