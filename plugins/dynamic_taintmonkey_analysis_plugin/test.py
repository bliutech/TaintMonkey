import test_app

if __name__ == '__main__':
    foo = test_app.example_source()
    better_foo = test_app.example_sanitizer(foo)
    test_app.example_sink(better_foo)
    dtm = test_app.dynamic_test
    dtm.monkey_patch_sanitizers()
    print(type(test_app.example_sanitizer(foo)))
    print(test_app.example_sanitizer(foo))