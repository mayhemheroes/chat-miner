#!/usr/bin/env python3
from json import JSONDecodeError

import atheris
import sys
import fuzz_helpers
import io
from contextlib import contextmanager

#with atheris.instrument_imports():
from chatminer.chatparsers import WhatsAppParser, SignalParser, TelegramHtmlParser, FacebookMessengerParser
from parser import ParserError

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 3)

    with nostdout():
        try:
            with fdp.ConsumeTemporaryFile('.txt', all_data=True, as_bytes=True) as file_path:
                if choice == 0:
                    parser = WhatsAppParser(file_path)
                    parser.parse_file_into_df()
                elif choice == 1:
                    parser = SignalParser(file_path)
                    parser.parse_file_into_df()
                elif choice == 2:
                    parser = TelegramHtmlParser(file_path)
                    parser.parse_file_into_df()
                elif choice == 3:
                    parser = FacebookMessengerParser(file_path)
                    parser.parse_file_into_df()
        except (KeyError, UnicodeDecodeError, ParserError, JSONDecodeError, ValueError, TypeError):
            return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
