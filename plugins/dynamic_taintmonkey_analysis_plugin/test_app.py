from dynamic_taintmonkey import DynamicTaintMonkey

dynamic_test = DynamicTaintMonkey()

secret_code = "Woah so secret"

@dynamic_test.source
def example_source():
    return "Yo"

@dynamic_test.sanitizer
def example_sanitizer(this_string, gurt = "yo"):
    if this_string == "Yo":
        return "Gurt"
    else:
        return this_string

@dynamic_test.sink
def example_sink(important_string):
    global secret_code
    secret_code = important_string