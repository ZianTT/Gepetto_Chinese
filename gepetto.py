import functools
import json
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import os
import re
import textwrap
import threading

# Set your API key here, or put in in the OPENAI_API_KEY environment variable.
openai.api_key = ""

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/Explain function"
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/Rename variables"
    wanted_name = 'Gepetto'
    wanted_hotkey = ''
    comment = "Uses davinci-003 to enrich the decompiler's output"
    help = "See usage instructions on GitHub"
    menu = None

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              '解释函数',
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              '使用 davinci-003 解释当前选择的函数',
                                              199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)

        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             '重命名变量',
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             "使用 davinci-003 重命名函数的变量",
                                             199)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.explain_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.rename_action_name, "Gepetto/")

# -----------------------------------------------------------------------------

def comment_callback(address, view, response):
    """
    Callback that sets a comment at the given address.
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add newlines at the end of each sentence.
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA.
    idc.set_func_cmt(address, response, 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("davinci-003 query finished!")


# -----------------------------------------------------------------------------

class ExplainHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying davinci-003 for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("你能解释一下下面的C函数是做什么的，并为它取一个更好的名字吗?\n"
                          + str(decompiler_output),
                          functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

def rename_callback(address, view, response):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from davinci-003
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        print(f"无法从响应中提取有效的JSON。正在使其修复…")
        query_model_async("此响应中提供的JSON是无效的。你能修复吗?\n" + response,
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=view))
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        print(f"返回的JSON无效。正在使其修复…")
        query_model_async("请修复以下JSON:\n" + j.group(0),
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=view))
        return

    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea

    replaced = []
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print(f"davinci-003 query finished! {len(replaced)} variable(s) renamed.")

# -----------------------------------------------------------------------------

class RenameHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from davinci-003 and updates the
    decompiler's output.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("分析下面的C函数:\n" + str(decompiler_output) +
                            "\n建议更好的变量名，回复一个JSON数组，其中键是原始名称，"
                            "值是建议的名称。不解释任何事情，只输出JSON"
                            "字典.",
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# =============================================================================
# davinci-003 interaction
# =============================================================================

def query_model(query, cb, max_tokens=2500):
    """
    Function which sends a query to davinci-003 and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=query,
            temperature=0.6,
            max_tokens=max_tokens,
            top_p=1,
            frequency_penalty=1,
            presence_penalty=1,
            timeout=60  # Wait 60 seconds maximum
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].text), ida_kernwin.MFF_WRITE)
    except openai.InvalidRequestError as e:
        # Context length exceeded. Determine the max number of tokens we can ask for and retry.
        m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                      r'prompt;', str(e))
        if not m:
            print(f"davinci-003 could not complete the request: {str(e)}")
            return
        (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
        max_tokens = hard_limit - prompt_tokens
        if max_tokens >= 750:
            print(f"Context length exceeded! Reducing the completion tokens to {max_tokens}...")
            query_model(query, cb, max_tokens)
        else:
            print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")

    except openai.OpenAIError as e:
        print(f"davinci-003 could not complete the request: {str(e)}")
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")

# -----------------------------------------------------------------------------

def query_model_async(query, cb):
    """
    Function which sends a query to davinci-003 and calls a callback when the response is available.
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    """
    print("Request to davinci-003 sent...")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()

# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    if not openai.api_key:
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print("Please edit this script to insert your OpenAI API key!")
            raise ValueError("No valid OpenAI API key found")

    return GepettoPlugin()
