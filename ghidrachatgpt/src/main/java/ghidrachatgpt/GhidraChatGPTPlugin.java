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

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.completion.chat.ChatMessageRole;
import com.theokanning.openai.service.OpenAiService;
import docking.Tool;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import java.lang.Integer;
import java.time.Duration;
import java.util.List;
import org.json.JSONObject;

//@formatter:off
@PluginInfo(status = PluginStatus.RELEASED,
            packageName = CorePluginPackage.NAME,
            category = PluginCategoryNames.ANALYSIS,
            shortDescription = "ChatGPT Plugin for Ghidra",
            description = "Brings the power of ChatGPT to Ghidra!",
            servicesRequired = {ConsoleService.class, CodeViewerService.class})

//@formatter:on
public class GhidraChatGPTPlugin extends ProgramPlugin {
  ConsoleService cs;
  CodeViewerService cvs;
  private GhidraChatGPTComponent uiComponent;
  private String apiToken;
  private String openAiModel = "gpt-3.5-turbo";
  private int OPENAI_TIMEOUT = 120;
  private static final String GCG_IDENTIFY_STRING =
      "Describe the function with as much detail as possible and include a link to an open source version if there is one\n %s";
  private static final String GCG_VULNERABILITY_STRING =
      "Describe all vulnerabilities in this function with as much detail as possible\n %s";
  private static final String GCG_BEAUTIFY_STRING =
      "Analyze the function and suggest function and variable names in a json format where the key is the previous name and the value is the suggested name\n %s";

  /**
   * Plugin constructor.
   *
   * @param tool The plugin tool that this plugin is added to.
   */
  public GhidraChatGPTPlugin(PluginTool tool) {
    super(tool);

    String pluginName = getName();
    uiComponent = new GhidraChatGPTComponent(this, pluginName);

    String topicName = this.getClass().getPackage().getName();
    String anchorName = "HelpAnchor";
    uiComponent.setHelpLocation(new HelpLocation(topicName, anchorName));
  }

  @Override
  public void init() {
    super.init();
    cs = tool.getService(ConsoleService.class);
    cvs = tool.getService(CodeViewerService.class);
    apiToken = System.getenv("OPENAI_TOKEN");
    if (apiToken != null)
      ok(String.format("Loaded OpenAI Token: %s", censorToken(apiToken)));
    ok(String.format("Default model is: %s", openAiModel));
  }

  public Boolean setToken(String token) {
    if (token == null)
      return false;

    apiToken = token;
    return true;
  }

  private static String censorToken(String token) {
    StringBuilder censoredBuilder = new StringBuilder(token.length());
    censoredBuilder.append(token.substring(0, 2));

    for (int i = 2; i < token.length(); i++) {
      censoredBuilder.append('*');
    }
    return censoredBuilder.toString();
  }

  public String getToken() { return apiToken; }

  public void setModel(String model) { openAiModel = model; }

  public void identifyFunction() {
    String result;
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null)
      return;

    log(String.format("Identifying the current function: %s",
                      decResult.func.getName()));
    result = askChatGPT(
        String.format(GCG_IDENTIFY_STRING, decResult.decompiledFunc));
    if (result == null)
      return;

    addComment(decResult.prog, decResult.func, result,
               "[GhidraChatGPT] - Identify Function");
  }

  public void findVulnerabilities() {
    String result;
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null)
      return;

    log(String.format("Finding vulnerabilities in the current function: %s",
                      decResult.func.getName()));
    result = askChatGPT(
        String.format(GCG_VULNERABILITY_STRING, decResult.decompiledFunc));
    if (result == null)
      return;

    addComment(decResult.prog, decResult.func, result,
               "[GhidraChatGPT] - Find Vulnerabilities");
  }

  public void beautifyFunction() {
    String result;
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null)
      return;

    log(String.format("Beautifying the function: %s",
                      decResult.func.getName()));
    result = askChatGPT(
        String.format(GCG_BEAUTIFY_STRING, decResult.decompiledFunc));
    if (result == null)
      return;

    updateVariables(decResult.prog, decResult, result);
    ok(String.format("Beautified the function: %s", decResult.func.getName()));
  }

  private Boolean checkOpenAIToken() {
    if (apiToken != null)
      return true;

    if (!setToken(uiComponent.askForOpenAIToken())) {
      error("Failed to update the OpenAI API token");
      return false;
    }
    return true;
  }

  private class DecompilerResults {
    public Program prog;
    public Function func;
    public String decompiledFunc;

    public DecompilerResults(Program prog, Function func,
                             String decompiledFunc) {
      this.prog = prog;
      this.func = func;
      this.decompiledFunc = decompiledFunc;
    }
  }

  private DecompilerResults decompileCurrentFunc() {
    String decompiledFunc;

    ProgramLocation progLoc = cvs.getCurrentLocation();
    Program prog = progLoc.getProgram();
    FlatProgramAPI programApi = new FlatProgramAPI(prog);
    FlatDecompilerAPI decompiler = new FlatDecompilerAPI(programApi);
    Function func = programApi.getFunctionContaining(progLoc.getAddress());
    if (func == null) {
      error("Failed to find the current function");
      return null;
    }

    try {
      decompiledFunc = decompiler.decompile(func);
    } catch (Exception e) {
      error(String.format(
          "Failed to decompile the function: %s with the error %s",
          func.getName(), e));
      return null;
    }

    return new DecompilerResults(prog, func, decompiledFunc);
  }

  private void updateVariables(Program prog, DecompilerResults decResult,
                               String result) {
    JSONObject jsonObj;

    try {
      jsonObj = new JSONObject(result);
    } catch (Exception e) {
      error("Failed to parse beautify JSON");
      return;
    }

    Variable[] vars = decResult.func.getAllVariables();
    if (vars == null) {
      log("Nothing to beautify");
      return;
    }

    var id = prog.startTransaction("GhidraChatGPT");
    for (Variable var : vars) {
      if (jsonObj.has(var.getName())) {
        String val = jsonObj.getString(var.getName());
        try {
          var.setName(val, SourceType.USER_DEFINED);
          ok(String.format("Beautified %s => %s", var.getName(), val));
        } catch (Exception e) {
          error(
              String.format("Failed to beautify %s => %s", var.getName(), val));
        }
      }
    };

    if (jsonObj.has(decResult.func.getName())) {
      String val = jsonObj.getString(decResult.func.getName());
      try {
        decResult.func.setName(val, SourceType.USER_DEFINED);
        ok(String.format("Beautified %s => %s", decResult.func.getName(), val));
      } catch (Exception e) {
        error(String.format("Failed to beautify %s => %s",
                            decResult.func.getName(), val));
      }
    }

    prog.endTransaction(id, true);
  }

  private void addComment(Program prog, Function func, String comment,
                          String commentHeader) {
    var id = prog.startTransaction("GhidraChatGPT");
    String currentComment = func.getComment();
    if (currentComment != null) {
      currentComment =
          String.format("%s\n%s\n\n%s", commentHeader, comment, currentComment);
    } else {
      currentComment = String.format("%s\n%s", commentHeader, comment);
    }

    func.setComment(currentComment);
    prog.endTransaction(id, true);
    ok(String.format(
        "Added the ChatGPT response as a comment to the function: %s",
        func.getName()));
  }

  private String askChatGPT(String prompt) {
    String response = sendOpenAIRequest(prompt);
    if (response == null) {
      error("The ChatGPT response was empty, try again!");
      return null;
    }

    return response;
  }

  private String sendOpenAIRequest(String prompt) {
    StringBuilder response = new StringBuilder();
    if (!checkOpenAIToken())
      return null;

    OpenAiService openAIService =
        new OpenAiService(apiToken, Duration.ofSeconds(OPENAI_TIMEOUT));
    if (openAIService == null) {
      error("Faild to start the OpenAI service, try again!");
      return null;
    }

    ChatCompletionRequest chatCompletionRequest =
        ChatCompletionRequest.builder()
            .model(openAiModel)
            .temperature(0.8)
            .messages(List.of(
                new ChatMessage(
                    ChatMessageRole.SYSTEM.value(),
                    "You are an assistant helping out with reverse engineering and vulnerability research"),
                new ChatMessage(ChatMessageRole.USER.value(), prompt)))
            .build();

    try {
      StringBuilder builder = new StringBuilder();
      openAIService.createChatCompletion(chatCompletionRequest)
          .getChoices()
          .forEach(
              choice -> { builder.append(choice.getMessage().getContent()); });

      return builder.toString();
    } catch (Exception e) {
      error(String.format("Asking ChatGPT failed with the error %s", e));
      return null;
    }
  }

  public void log(String message) {
    cs.println(String.format("%s [>] %s", getName(), message));
  }

  public void error(String message) {
    cs.println(String.format("%s [-] %s", getName(), message));
  }

  public void ok(String message) {
    cs.println(String.format("%s [+] %s", getName(), message));
  }
}
