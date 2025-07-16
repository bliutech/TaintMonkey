"""
CWD (Current Working Directory) should be TaintMonkey (parent of plugins)
"""

import plugins.dynamic_taintmonkey_analysis_plugin.test_app

test_app = plugins.dynamic_taintmonkey_analysis_plugin.test_app
from taintmonkey.patch import patch_function
from taintmonkey.taint import TaintedStr

old_example_yo = plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_yo


@patch_function("plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_yo")
def new_example_yo(this_string: TaintedStr, gurt="yo"):
    print("Gurt!")
    return TaintedStr(old_example_yo(this_string, gurt))


print(test_app.example_yo)
print(plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_yo)

if __name__ == "__main__":
    test_app.example_yo("hi")
    plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_yo("hi")
    print()

    test_app.run_example()
    foo = test_app.example_source()
    print(f"First source: {foo} - Type: {type(foo)} - Tainted?: {foo.is_tainted()}")
    better_foo = test_app.example_sanitizer(foo)
    print(
        f"After sanitizer: {better_foo} - Type: {type(better_foo)} - Tainted?: {better_foo.is_tainted()}"
    )
    test_app.example_sink(better_foo)
    print("Sink: No error! Clean")
    print()

    # bar = test_app.example_sink(TaintedStr("Hello")) #Uncomment - will cause error

    # Example that involves some modification
    skib = test_app.example_source()
    skib = test_app.random_process(skib)
    skib = test_app.example_sanitizer(skib)  # Commenting this out will cause error

    dtm = test_app.dynamic_test
    f = dtm.get_function_from_path(
        "plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_sanitizer"
    )
    print(plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_sanitizer)
    print(f)
    print(type(f))
    print(f("Yo"))
    print()
    dtm.monkey_patch_sanitizers()
    print(
        f"1: {plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_sanitizer}"
    )
    plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_sanitizer("hi")
    print(f"2: {test_app.example_sanitizer}")
    test_app.example_sanitizer("hi!")
    print(
        f"3: {plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_sanitizer}"
    )
    plugins.dynamic_taintmonkey_analysis_plugin.test_app.example_sanitizer("hi")
