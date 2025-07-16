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


class Fuzzer(ABC):
    def __init__(self, app: Flask, corpus: str):
        self.flask_app = app
        self.corpus = corpus
        self.inputs = []
        self.load_corpus()

    def load_corpus(self):
        if not os.path.exists(self.corpus):
            raise FileNotFoundError(f"Corpus file not found: {self.corpus}")
        with open(self.corpus, "r") as f:
            self.inputs = [line.strip() for line in f if line.strip()]

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
