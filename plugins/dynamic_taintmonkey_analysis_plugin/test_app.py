from dynamic_taintmonkey import DynamicTaintMonkey
from random import randint

dynamic_test = DynamicTaintMonkey()

secret_code = "Woah so secret"

@dynamic_test.source
def example_source():
    return "Yo"

@dynamic_test.sanitizer(sanitizer_type="sanitizer")
def example_sanitizer(this_string, gurt = "yo"):
    if this_string == "Yo":
        return "Gurt"
    else:
        return this_string

@dynamic_test.sink
def example_sink(important_string):
    global secret_code
    secret_code = important_string
    return secret_code

def random_process(given_string):
    for i in range(0, 10):
        given_string = given_string + str(randint(0, 10))
    return given_string