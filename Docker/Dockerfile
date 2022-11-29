FROM debian:bookworm-slim
ENV PATH /home/checker/bin:/home/checker/.local/bin:$PATH
ENV LANG C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        apt-transport-https ca-certificates python3 pip\
        && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY pkg/*.tar.gz /tmp
COPY scripts/cmd.sh /
RUN groupadd -g 1001 checker && useradd -ms /bin/bash -u 1001 -g 1001 checker
RUN su - checker -c "pip install --user --no-warn-script-location /tmp/cloudheadschecker*.tar.gz"
USER checker
WORKDIR /home/checker/

CMD ["/cmd.sh"]
