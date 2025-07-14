import test_app
from taintmonkey.taint import TaintedStr

if __name__ == '__main__':

    foo = test_app.example_source()
    better_foo = test_app.example_sanitizer(foo)
    test_app.example_sink(better_foo)

    #bar = test_app.example_sink(TaintedStr("Hello")) #Uncomment - will cause error

    #Example that involves some modification

    skib = test_app.example_source()
    skib = test_app.random_process(skib)
    skib = test_app.example_sanitizer(skib) #Commenting this out will cause error
    print(test_app.example_sink(skib))


    dtm = test_app.dynamic_test
    dtm.monkey_patch_sanitizers()