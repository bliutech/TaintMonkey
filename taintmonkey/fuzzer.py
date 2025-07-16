# TODO(bliutech): need to implement the following patterns / structure
# do via dependency injection?
# - executor
# - observer
# - mutator (start with a NoOp mutator where it just uses the corpus as a dictionary)

# For now, we have a primitive structure with a dictionary fuzzer.

from abc import ABC, abstractmethod
from contextlib import contextmanager
import random
import os

from flask import Flask
# from taintmonkey.client import register_taint_client
from client import register_taint_client

from grammar_based_fuzzing.JSONGenerator import JSONGenerator
from grammarinator.tool import DefaultGeneratorFactory, GeneratorTool


class Fuzzer(ABC):
    def __init__(self, app: Flask, corpus: str):
        self.flask_app = app
        self.corpus = corpus
        self.inputs = []
        # self.load_corpus()

    # def load_corpus(self):
    #     if not os.path.exists(self.corpus):
    #         raise FileNotFoundError(f"Corpus file not found: {self.corpus}")
    #     with open(self.corpus, "r") as f:
    #         self.inputs = [line.strip() for line in f if line.strip()]

    @abstractmethod
    def get_context(self):
        pass


class DictionaryFuzzer(Fuzzer):
    @contextmanager
    def get_context(self):  # type: ignore
        # Choose a random input from the dictionary
        random.shuffle(self.inputs)
        test_client = self.flask_app.test_client()

        yield (test_client, self.inputs)

class GrammarBasedFuzzer(Fuzzer):
    @contextmanager
    def get_context(self):  # type: ignore
        # Choose a random input from the dictionary
        factory = DefaultGeneratorFactory(generator_class=JSONGenerator)
        tool = GeneratorTool(
            generator_factory=factory,
            out_format="",           
            rule="json",          
            max_depth=5,
            keep_trees=False,
            cleanup=False,
        )

        self.inputs = []
        test_client = self.flask_app.test_client()

        for i in range(5):
            out = tool.create(i)
            self.inputs.append(out)

        yield (test_client, self.inputs)

if __name__ == "__main__":
    app = Flask(__name__)
    g = GrammarBasedFuzzer(app, "test_corpus.txt")

    with g.get_context() as (_, inputs):
        for input in inputs:
            print(input)

