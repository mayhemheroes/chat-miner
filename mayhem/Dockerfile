# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9

ADD . /src
WORKDIR /src
RUN python3 -m pip install chat-miner

CMD ["/src/mayhem/fuzz_app.py"]
