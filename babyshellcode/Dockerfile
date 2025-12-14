FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y socat

RUN useradd -m ctf
COPY ./vuln /home/ctf
COPY ./flag.txt /home/ctf

WORKDIR /home/ctf/
RUN chmod +x /home/ctf/vuln

USER ctf
EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/vuln,stderr"]