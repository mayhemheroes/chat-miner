#!/usr/bin/env python3
from json import JSONDecodeError

import atheris
import io
import sys
import fuzz_helpers
import warnings
import logging

logging.disable(logging.CRITICAL)


from contextlib import contextmanager
with atheris.instrument_imports(include=['chatminer']):
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
    try:
        with fdp.ConsumeTemporaryFile('.txt', all_data=True, as_bytes=False) as file_path, nostdout(), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if choice == 0:
                parser = WhatsAppParser(file_path)
            elif choice == 1:
                parser = SignalParser(file_path)
            elif choice == 2:
                parser = TelegramHtmlParser(file_path)
            elif choice == 3:
                parser = FacebookMessengerParser(file_path)
            parser.parse_file_into_df()
    except (KeyError, UnicodeDecodeError, ParserError, JSONDecodeError, ValueError, TypeError):
        return -1
    except AttributeError as e:
        if 'dt' in str(e):
            return -1
        raise

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
